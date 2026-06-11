import json
import os
from typing import Any, Callable

import httpx

from app.adapters.fake import LocalMockLlmProvider
from app.core.config import Settings
from app.models import KnowledgeArticle, Ticket


class ExternalProviderConfigError(RuntimeError):
    """Raised when an optional live LLM provider is selected but not configured."""


class ExternalProviderCallError(RuntimeError):
    """Raised when an optional live LLM provider fails before a draft is produced."""


class OpenAIChatProvider:
    provider_name = "openai"

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        timeout_seconds: float,
        max_tokens: int,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ):
        if not api_key:
            raise ExternalProviderConfigError("OpenAI provider selected without an API key.")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        self.client_factory = client_factory

    async def draft_customer_reply(self, ticket: Ticket, context: list[KnowledgeArticle]) -> dict[str, Any]:
        return await self._chat(
            system=(
                "You draft support replies for an enterprise support control tower. "
                "Stay grounded in the supplied KB context, cite article IDs inline, "
                "and make clear that a human reviewer must approve the message."
            ),
            user=self._customer_prompt(ticket, context),
        )

    async def draft_engineering_escalation(
        self,
        ticket: Ticket,
        classification: dict[str, Any],
        sla_risk: dict[str, Any],
        context: list[KnowledgeArticle],
    ) -> dict[str, Any]:
        return await self._chat(
            system=(
                "You draft engineering escalations for support incidents. Include severity, "
                "customer impact, suspected area, reproduction clues, KB citations, and "
                "explicitly keep the ticket pending human approval."
            ),
            user=self._engineering_prompt(ticket, classification, sla_risk, context),
        )

    async def _chat(self, system: str, user: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": self.max_tokens,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        try:
            if self.client_factory:
                async with self.client_factory() as client:
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json=payload,
                    )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json=payload,
                    )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ExternalProviderCallError(f"OpenAI provider call failed: {exc}") from exc
        return self._provider_result(data, payload)

    def _provider_result(self, data: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        choices = data.get("choices") or []
        message = choices[0].get("message", {}) if choices else {}
        text = (message.get("content") or "").strip()
        if not text:
            raise ExternalProviderCallError("OpenAI provider returned an empty draft.")
        usage = data.get("usage") or {}
        tokens = int(usage.get("total_tokens") or self._rough_tokens(payload, text))
        return {
            "text": text,
            "tokens": tokens,
            "cost_usd": self._estimate_cost(tokens),
            "provider": self.provider_name,
            "model": self.model,
            "fallback_used": False,
        }

    def _customer_prompt(self, ticket: Ticket, context: list[KnowledgeArticle]) -> str:
        return "\n\n".join(
            [
                f"Ticket: {ticket.ticket_id}",
                f"Subject: {ticket.subject}",
                f"Priority: {ticket.priority}",
                f"Customer tier: {ticket.customer_tier}",
                f"Body: {ticket.body}",
                "KB context:",
                self._context_block(context),
            ]
        )

    def _engineering_prompt(
        self,
        ticket: Ticket,
        classification: dict[str, Any],
        sla_risk: dict[str, Any],
        context: list[KnowledgeArticle],
    ) -> str:
        return "\n\n".join(
            [
                f"Ticket: {ticket.ticket_id}",
                f"Subject: {ticket.subject}",
                f"Category: {classification.get('category')}",
                f"SLA risk: {sla_risk.get('level')} ({sla_risk.get('score')})",
                f"Reasons: {', '.join(sla_risk.get('reasons', []))}",
                f"Body: {ticket.body}",
                "KB context:",
                self._context_block(context),
            ]
        )

    def _context_block(self, context: list[KnowledgeArticle]) -> str:
        rows = [
            {
                "article_id": item.article_id,
                "title": item.title,
                "content": item.content[:1000],
                "score": item.score,
            }
            for item in context[:5]
        ]
        return json.dumps(rows, indent=2)

    def _rough_tokens(self, payload: dict[str, Any], text: str) -> int:
        prompt_words = sum(len(message.get("content", "").split()) for message in payload["messages"])
        return max(1, round((prompt_words + len(text.split())) * 1.25))

    def _estimate_cost(self, tokens: int) -> float:
        return round(tokens * 0.000001, 6)


class AzureOpenAIChatProvider(OpenAIChatProvider):
    provider_name = "azure_openai"

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str,
        timeout_seconds: float,
        max_tokens: int,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ):
        if not endpoint or not api_key or not deployment:
            raise ExternalProviderConfigError(
                "Azure OpenAI provider selected without endpoint, API key, or deployment."
            )
        super().__init__(
            api_key=api_key,
            model=deployment,
            base_url=endpoint,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
            client_factory=client_factory,
        )
        self.api_version = api_version

    async def _chat(self, system: str, user: str) -> dict[str, Any]:
        payload = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": self.max_tokens,
        }
        headers = {"api-key": self.api_key, "Content-Type": "application/json"}
        url = (
            f"{self.base_url}/openai/deployments/{self.model}/chat/completions"
            f"?api-version={self.api_version}"
        )
        try:
            if self.client_factory:
                async with self.client_factory() as client:
                    response = await client.post(url, headers=headers, json=payload)
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ExternalProviderCallError(f"Azure OpenAI provider call failed: {exc}") from exc
        return self._provider_result(data, payload)


class FallbackLlmProvider:
    provider_name = "fallback"

    def __init__(self, primary: Any, fallback: LocalMockLlmProvider, reason: str = ""):
        self.primary = primary
        self.fallback = fallback
        self.reason = reason

    async def draft_customer_reply(self, ticket: Ticket, context: list[KnowledgeArticle]) -> dict[str, Any]:
        if self.reason:
            return await self._fallback_result(
                self.fallback.draft_customer_reply(ticket, context),
                self.reason,
            )
        try:
            return await self.primary.draft_customer_reply(ticket, context)
        except (ExternalProviderConfigError, ExternalProviderCallError, httpx.HTTPError) as exc:
            return await self._fallback_result(
                self.fallback.draft_customer_reply(ticket, context),
                f"{self.reason or self.primary.__class__.__name__}: {exc}",
            )

    async def draft_engineering_escalation(
        self,
        ticket: Ticket,
        classification: dict[str, Any],
        sla_risk: dict[str, Any],
        context: list[KnowledgeArticle],
    ) -> dict[str, Any]:
        if self.reason:
            return await self._fallback_result(
                self.fallback.draft_engineering_escalation(ticket, classification, sla_risk, context),
                self.reason,
            )
        try:
            return await self.primary.draft_engineering_escalation(
                ticket,
                classification,
                sla_risk,
                context,
            )
        except (ExternalProviderConfigError, ExternalProviderCallError, httpx.HTTPError) as exc:
            return await self._fallback_result(
                self.fallback.draft_engineering_escalation(ticket, classification, sla_risk, context),
                f"{self.reason or self.primary.__class__.__name__}: {exc}",
            )

    async def _fallback_result(self, fallback_call: Any, reason: str) -> dict[str, Any]:
        result = await fallback_call
        result.update(
            {
                "provider": "local",
                "model": "LocalMockLlmProvider",
                "fallback_used": True,
                "fallback_reason": reason[:500],
            }
        )
        return result


class BlockingLlmProvider:
    provider_name = "blocked"

    def __init__(self, reason: str):
        self.reason = reason

    async def draft_customer_reply(self, ticket: Ticket, context: list[KnowledgeArticle]) -> dict[str, Any]:
        raise ExternalProviderConfigError(self.reason)

    async def draft_engineering_escalation(
        self,
        ticket: Ticket,
        classification: dict[str, Any],
        sla_risk: dict[str, Any],
        context: list[KnowledgeArticle],
    ) -> dict[str, Any]:
        raise ExternalProviderConfigError(self.reason)


def build_llm_provider(settings: Settings) -> Any:
    configured = settings.llm_provider.strip().lower() or "local"
    fallback = LocalMockLlmProvider()
    if configured in {"local", "mock"}:
        return fallback
    try:
        if configured == "openai":
            primary = OpenAIChatProvider(
                api_key=_first_value(settings.openai_api_key, "OPENAI_API_KEY", "CONTROL_TOWER_OPENAI_API_KEY"),
                model=settings.openai_model,
                base_url=settings.openai_base_url,
                timeout_seconds=settings.llm_timeout_seconds,
                max_tokens=settings.llm_max_tokens,
            )
        elif configured in {"azure", "azure_openai"}:
            primary = AzureOpenAIChatProvider(
                endpoint=_first_value(
                    settings.azure_openai_endpoint,
                    "AZURE_OPENAI_ENDPOINT",
                    "CONTROL_TOWER_AZURE_OPENAI_ENDPOINT",
                ),
                api_key=_first_value(
                    settings.azure_openai_api_key,
                    "AZURE_OPENAI_API_KEY",
                    "CONTROL_TOWER_AZURE_OPENAI_API_KEY",
                ),
                deployment=settings.azure_openai_deployment,
                api_version=settings.azure_openai_api_version,
                timeout_seconds=settings.llm_timeout_seconds,
                max_tokens=settings.llm_max_tokens,
            )
        else:
            raise ExternalProviderConfigError(f"Unsupported LLM provider `{configured}`.")
    except ExternalProviderConfigError as exc:
        if not settings.llm_fallback_enabled:
            return BlockingLlmProvider(str(exc))
        return FallbackLlmProvider(primary=fallback, fallback=fallback, reason=str(exc))
    if settings.llm_fallback_enabled:
        return FallbackLlmProvider(primary=primary, fallback=fallback)
    return primary


def provider_runtime_class(settings: Settings) -> str:
    provider = build_llm_provider(settings)
    if isinstance(provider, BlockingLlmProvider):
        return "ProviderConfigBlocked"
    if isinstance(provider, FallbackLlmProvider) and provider.primary is provider.fallback:
        return provider.fallback.__class__.__name__
    if isinstance(provider, FallbackLlmProvider):
        return f"{provider.primary.__class__.__name__}+LocalMockFallback"
    return provider.__class__.__name__


def _first_value(settings_value: str, *env_names: str) -> str:
    return settings_value or next((os.getenv(name, "") for name in env_names if os.getenv(name)), "")
