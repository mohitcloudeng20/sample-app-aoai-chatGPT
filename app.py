import copy
import json
import os
import logging
import uuid
import httpx
import asyncio
from quart import (
    Blueprint,
    Quart,
    jsonify,
    make_response,
    request,
    send_from_directory,
    render_template,
    current_app,
)

from openai import AsyncAzureOpenAI
from azure.identity.aio import DefaultAzureCredential, get_bearer_token_provider
from backend.auth.auth_utils import get_authenticated_user_details
from backend.security.ms_defender_utils import get_msdefender_user_json
from backend.settings import app_settings, MINIMUM_SUPPORTED_AZURE_OPENAI_PREVIEW_API_VERSION
from backend.utils import (
    format_as_ndjson,
    format_stream_response,
    format_non_streaming_response,
    convert_to_pf_format,
    format_pf_non_streaming_response,
)

bp = Blueprint("routes", __name__, static_folder="static", template_folder="static")

def create_app():
    app = Quart(__name__)
    app.register_blueprint(bp)
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    return app

@bp.route("/")
async def index():
    return await render_template("index.html", title=app_settings.ui.title, favicon=app_settings.ui.favicon)

@bp.route("/favicon.ico")
async def favicon():
    return await bp.send_static_file("favicon.ico")

@bp.route("/assets/<path:path>")
async def assets(path):
    return await send_from_directory("static/assets", path)

DEBUG = os.environ.get("DEBUG", "false")
if DEBUG.lower() == "true":
    logging.basicConfig(level=logging.DEBUG)

USER_AGENT = "GitHubSampleWebApp/AsyncAzureOpenAI/1.0.0"

frontend_settings = {
    "auth_enabled": app_settings.base_settings.auth_enabled,
    "ui": {
        "title": app_settings.ui.title,
        "logo": app_settings.ui.logo,
        "chat_logo": app_settings.ui.chat_logo or app_settings.ui.logo,
        "chat_title": app_settings.ui.chat_title,
        "chat_description": app_settings.ui.chat_description,
        "show_share_button": app_settings.ui.show_share_button,
        "show_chat_history_button": app_settings.ui.show_chat_history_button,
    },
    "sanitize_answer": app_settings.base_settings.sanitize_answer,
    "oyd_enabled": app_settings.base_settings.datasource_type,
}

MS_DEFENDER_ENABLED = os.environ.get("MS_DEFENDER_ENABLED", "true").lower() == "true"

@bp.route("/webhook", methods=["POST"])
async def google_chat_webhook():
    try:
        request_json = await request.get_json()
        event_type = request_json.get("type")

        if event_type == "MESSAGE":
            user_message = request_json.get("message", {}).get("text", "")
            user_name = request_json.get("message", {}).get("sender", {}).get("displayName", "User")
            response_text = await handle_google_chat_message(user_message, user_name)
            return jsonify({"text": response_text})
        elif event_type == "ADDED_TO_SPACE":
            space_name = request_json.get("space", {}).get("name", "unknown space")
            return jsonify({"text": f"Thanks for adding me to {space_name}!"})
        elif event_type == "REMOVED_FROM_SPACE":
            return jsonify({})
        else:
            return jsonify({"text": "I didn't understand that event type."})
    except Exception as e:
        logging.exception("Error handling Google Chat webhook")
        return jsonify({"error": str(e)}), 500

async def handle_google_chat_message(user_message, user_name):
    try:
        azure_openai_client = await init_openai_client()
        response = await azure_openai_client.chat.completions.create(
            model=app_settings.azure_openai.model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": user_message}
            ],
            max_tokens=150
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logging.exception("Error in Azure OpenAI response")
        return "Sorry, I couldn't process your message."

async def init_openai_client():
    try:
        if app_settings.azure_openai.preview_api_version < MINIMUM_SUPPORTED_AZURE_OPENAI_PREVIEW_API_VERSION:
            raise ValueError("The minimum supported Azure OpenAI preview API version is exceeded.")
        
        endpoint = (
            app_settings.azure_openai.endpoint if app_settings.azure_openai.endpoint
            else f"https://{app_settings.azure_openai.resource}.openai.azure.com/"
        )
        
        aoai_api_key = app_settings.azure_openai.key
        ad_token_provider = None
        if not aoai_api_key:
            async with DefaultAzureCredential() as credential:
                ad_token_provider = get_bearer_token_provider(credential, "https://cognitiveservices.azure.com/.default")
        
        deployment = app_settings.azure_openai.model
        
        default_headers = {"x-ms-useragent": USER_AGENT}
        
        azure_openai_client = AsyncAzureOpenAI(
            api_version=app_settings.azure_openai.preview_api_version,
            api_key=aoai_api_key,
            azure_ad_token_provider=ad_token_provider,
            default_headers=default_headers,
            azure_endpoint=endpoint,
        )
        return azure_openai_client
    except Exception as e:
        logging.exception("Exception in Azure OpenAI initialization", e)
        raise e

@bp.route("/conversation", methods=["POST"])
async def conversation():
    if not request.is_json:
        return jsonify({"error": "request must be json"}), 415
    request_json = await request.get_json()
    return await conversation_internal(request_json, request.headers)

async def conversation_internal(request_body, request_headers):
    try:
        if app_settings.azure_openai.stream:
            result = await stream_chat_request(request_body, request_headers)
            response = await make_response(format_as_ndjson(result))
            response.timeout = None
            response.mimetype = "application/json-lines"
            return response
        else:
            result = await complete_chat_request(request_body, request_headers)
            return jsonify(result)
    except Exception as ex:
        logging.exception(ex)
        return jsonify({"error": str(ex)}), 500

app = create_app()
