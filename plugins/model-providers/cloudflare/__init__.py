"""Cloudflare Workers AI provider profile."""

import os
from typing import Any

from providers import register_provider
from providers.base import ProviderProfile


class CloudflareProfile(ProviderProfile):
    """Cloudflare Workers AI — requires account_id in base_url."""

    def fetch_models(
        self,
        *,
        api_key: str | None = None,
        timeout: float = 8.0,
    ) -> list[str] | None:
        """Cloudflare's /models endpoint requires account_id in the URL."""
        from hermes_cli.config import get_env_value
        from hermes_cli.models import _fetch_cloudflare_models
        
        account_id = get_env_value("CLOUDFLARE_ACCOUNT_ID")
        if not account_id or not api_key:
            return None

        # Use the specific Cloudflare search API for dynamic discovery
        return _fetch_cloudflare_models(api_key, account_id, timeout=timeout)


cloudflare = CloudflareProfile(
    name="cloudflare",
    aliases=("cf", "cloudflare-ai"),
    display_name="Cloudflare Workers AI",
    description="Cloudflare Workers AI — serverless GPU inference",
    signup_url="https://dash.cloudflare.com/?to=/:account/ai/workers-ai/models",
    env_vars=("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"),
    # base_url is dynamic; placeholder for registry
    base_url="https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
    fallback_models=(
        "@cf/meta/llama-3.1-8b-instruct",
        "@cf/meta/llama-3.1-70b-instruct",
        "@cf/meta/llama-3-8b-instruct",
        "@cf/mistral/mistral-7b-instruct-v0.1",
        "@hf/nousresearch/hermes-2-pro-llama-3-8b",
    ),
)

register_provider(cloudflare)
