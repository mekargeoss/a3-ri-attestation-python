# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client


class A3Issuer:
    def __init__(self, issuer_path: str):
        self.__issuer_url = (
            f"https://a3.mekarge.com/auth/{issuer_path.rstrip('/')}"
        )
        self.__configuration_url = (
            f"{self.__issuer_url}/.well-known/openid-configuration"
        )

    def issuer_url(self) -> str:
        return self.__issuer_url

    def configuration_url(self) -> str:
        return self.__configuration_url


class A3Client:
    def __init__(
        self, issuer: A3Issuer, client_id: str, client_secret: str | None = None
    ):
        self.issuer_url = issuer.configuration_url()
        self.client_id = client_id
        self.client_secret = client_secret
        self._discovery: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None

    async def get_configuration(self) -> dict[str, Any]:
        if self._discovery is None:
            discovery: dict[str, Any] = dict()
            async with httpx.AsyncClient(timeout=10, verify=True) as client:
                response = await client.get(self.issuer_url)
                response.raise_for_status()
                discovery = response.json()
                self._discovery = discovery
            return discovery
        return self._discovery

    async def get_jwks(self) -> dict[str, Any]:
        if self._jwks is None:
            jwks: dict[str, Any] = dict()
            discovery = await self.get_configuration()
            jwks_uri = discovery["jwks_uri"]
            async with httpx.AsyncClient(timeout=10, verify=True) as client:
                response = await client.get(jwks_uri)
                response.raise_for_status()
                jwks = response.json()
                self._jwks = jwks
            return jwks
        return self._jwks

    async def build_authorize_url(
        self,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
        nonce: str,
        claims_locales: str | None = None,
        ui_locales: str | None = None,
    ) -> str:
        discovery = await self.get_configuration()
        auth_endpoint = discovery["authorization_endpoint"]
        from urllib.parse import urlencode

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "login_hint": "email",
        }
        if claims_locales:
            params["claim_locales"] = claims_locales
        if ui_locales:
            params["ui_locale"] = ui_locales
        return f"{auth_endpoint}?{urlencode(params)}"

    async def request_access_token(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        state: str,
        ear_token: str,
        at_profile: str | None,
    ) -> dict[str, Any]:
        discovery = await self.get_configuration()
        token_endpoint = discovery["token_endpoint"]
        async with AsyncOAuth2Client(
            client_id=self.client_id,
            client_secret=self.client_secret,
            timeout=10,
            verify=True,
        ) as client:
            token: dict[str, Any] = await client.fetch_token(
                url=token_endpoint,
                grant_type="authorization_code",
                token_endpoint_auth_method="client_secret_post",
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                state=state,
                attestation_result=ear_token,
                attestation_profile=at_profile,
            )
            return token
