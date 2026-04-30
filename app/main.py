# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import time
import urllib.parse
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.a3_client import A3Client, A3Issuer
from app.crypto_utils import compute_jwk_thumbprint
from app.generators import (
    gen_challenge_nonce,
    gen_handoff_code,
    gen_login_code,
    gen_nonce,
    gen_pkce_challenge,
    gen_session_token,
    gen_state,
)
from app.model import (
    AttestationResult,
    AuthorizationCode,
    AuthorizationParameters,
    LoginCode,
    Session,
    SessionToken,
    State,
)
from app.payload import (
    AttestationChallengeRequest,
    AttestationChallengeResponse,
    AttestationVerifyRequest,
    AttestationVerifyResponse,
    AuthFinishRequest,
    ErrorResponse,
    SessionTokenResponse,
)
from app.security import (
    InvalidDPoP,
    InvalidToken,
    validate_dpop_jwt,
    validate_token_jwt,
)
from app.settings import settings
from app.storage import (
    get_session,
    pop_attestation_result,
    pop_authz_parameters,
    pop_challenge,
    pop_handoff_code,
    pop_login_code,
    put_attestation_result,
    put_authz_parameters,
    put_challenge,
    put_handoff_code,
    put_login_code,
    put_session,
    revoke_session,
)
from app.time.helpers import expires_after, now
from app.time.model import TTL
from app.verifier.app_verifier import calculate_expiry, verify_app
from app.verifier.ear import build_ear_jwt
from app.verifier.model import Platform
from app.verifier.settings import settings as verifier_settings

app = FastAPI(title="BFF Reference Backend")
a3_issuer = A3Issuer(settings.issuer_path)
a3_client = A3Client(a3_issuer, settings.client_id, settings.client_secret)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def validate_dpop(request: Request) -> SessionToken:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401, detail="Missing authorization header"
        )

    session_token = SessionToken(auth_header.split(" ", 1)[1])

    session = get_session(session_token)
    if not session:
        raise HTTPException(
            status_code=401, detail="Invalid/expired session token"
        )
    jkt_expected = session.jkt

    dpop = request.headers.get("dpop")
    if not dpop:
        raise HTTPException(status_code=401, detail="Missing Dpop header")

    url = str(request.url)
    try:
        validate_dpop_jwt(dpop, request.method, url, jkt_expected)
    except InvalidDPoP as e:
        raise HTTPException(
            status_code=401, detail="DPoP validation failed"
        ) from e

    return session_token


async def validate_token(token: str, nonce: str | None, expected_aud: str):
    jwks = await a3_client.get_jwks()
    claims = validate_token_jwt(
        token=token,
        issuer=a3_issuer,
        nonce=nonce,
        jwks=jwks,
        expected_aud=expected_aud,
    )
    return claims


@app.post(
    "/attestation/challenge",
    response_model=AttestationChallengeResponse,
    responses={400: {"model": ErrorResponse}},
)
async def attestation_challenge(body: AttestationChallengeRequest):
    jkt = compute_jwk_thumbprint(body.public_jwk)
    challenge_nonce = gen_challenge_nonce()
    put_challenge(jkt, challenge_nonce, ttl=TTL(300))
    return AttestationChallengeResponse(jkt=jkt, nonce=challenge_nonce)


@app.post(
    "/attestation/verify",
    response_model=AttestationVerifyResponse,
    responses={400: {"model": ErrorResponse}},
)
async def session_bootstrap(body: AttestationVerifyRequest):
    """
    Notes:
    - Can use device info for additional Appraisals
    """
    nonce = pop_challenge(body.jkt)
    if not nonce:
        raise HTTPException(status_code=400, detail="Missing challenge nonce")

    appraisal = await verify_app(
        body.platform, body.evidences, expected_nonce=nonce
    )
    attestation_appraisals = [appraisal] if appraisal is not None else []
    attestation_expiry = calculate_expiry(attestation_appraisals)

    if not attestation_expiry:
        raise HTTPException(
            status_code=400,
            detail="Attestation Result is not sufficient to continue to flow",
        )

    put_attestation_result(
        jkt=body.jkt,
        result=AttestationResult(
            created_at=int(time.time()),
            platform=body.platform,
            appraisals=attestation_appraisals,
            expires_at=attestation_expiry,
        ),
    )

    login_code = gen_login_code()
    put_login_code(login_code, jkt=body.jkt, ttl=TTL(300))

    return AttestationVerifyResponse(
        login_start_url=f"{settings.base_url}/auth/start?login={urllib.parse.quote(login_code)}"
    )


@app.get("/auth/start")
async def auth_start(login: LoginCode):
    jkt = pop_login_code(login)
    if not jkt:
        raise HTTPException(
            status_code=400, detail="Invalid/expired login code"
        )

    state = gen_state()
    nonce = gen_nonce()
    pkce_verifier, pkce_challenge = gen_pkce_challenge()

    authorize_url = await a3_client.build_authorize_url(
        redirect_uri=settings.redirect_uri,
        scope="openid profile email",
        state=state,
        code_challenge=pkce_challenge,
        code_challenge_method="S256",
        nonce=nonce,
        claims_locales=None,
        ui_locales=None,
    )

    parameters = AuthorizationParameters(
        jkt=jkt, pkce_verifier=pkce_verifier, nonce=nonce
    )
    put_authz_parameters(state, parameters)

    return RedirectResponse(url=authorize_url, status_code=302)


@app.get("/callback")
async def callback(code: AuthorizationCode, state: State):
    parameters = pop_authz_parameters(state)
    if not parameters:
        raise HTTPException(status_code=400, detail="Invalid state")

    attestation = pop_attestation_result(parameters.jkt)
    if not attestation:
        raise HTTPException(
            status_code=400, detail="Attestation result not found"
        )

    if attestation.expires_at < now():
        raise HTTPException(
            status_code=400, detail="Attestation result is expired"
        )

    ear_token = build_ear_jwt(
        verifier_settings.verifier_secret, attestation.appraisals
    )

    match attestation.platform:
        case Platform.android:
            attestation_profile = verifier_settings.android_attestation_profile
        case Platform.ios:
            attestation_profile = verifier_settings.ios_attestation_profile

    try:
        token_response = await a3_client.request_access_token(
            code=code,
            redirect_uri=settings.redirect_uri,
            state=state,
            code_verifier=parameters.pkce_verifier,
            ear_token=ear_token,
            at_profile=attestation_profile,
        )
    except Exception as e:
        raise HTTPException(
            status_code=400, detail="Failed to get access token from Mekarge A3"
        ) from e

    try:
        access_claims = await validate_token(
            token=token_response["access_token"],
            nonce=None,
            expected_aud=settings.resource_uri,
        )
    except InvalidToken as e:
        raise HTTPException(
            status_code=400, detail="Failed to validate access token"
        ) from e

    try:
        id_claims = await validate_token(
            token=token_response["id_token"],
            nonce=parameters.nonce,
            expected_aud=settings.client_id,
        )
    except InvalidToken as e:
        raise HTTPException(
            status_code=400, detail="Failed to validate id token"
        ) from e

    session_token = gen_session_token()
    session_expires_at = expires_after(TTL(3600))
    put_session(
        session_token,
        Session(
            jkt=parameters.jkt,
            user_name=id_claims.get("name"),
            user_email=id_claims.get("email"),
            scopes=access_claims.get("scope", "").split(" "),
            expires_at=session_expires_at,
        ),
    )

    handoff_code = gen_handoff_code()
    put_handoff_code(handoff_code, session_token=session_token, ttl=TTL(300))

    deeplink = (
        f"{settings.deeplink_url}?code={urllib.parse.quote(handoff_code)}"
    )
    return RedirectResponse(url=deeplink, status_code=302)


@app.post(
    "/auth/finish",
    response_model=SessionTokenResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)
async def auth_finish(req: Request, body: AuthFinishRequest):
    session_token = pop_handoff_code(body.app_handoff_code)
    if not session_token:
        raise HTTPException(
            status_code=400, detail="Invalid/expired handoff code"
        )

    session = get_session(session_token)
    if not session:
        raise HTTPException(status_code=400, detail="Session expired")

    expected_jkt = session.jkt

    dpop = req.headers.get("dpop")
    if not dpop:
        raise HTTPException(status_code=400, detail="Missing Dpop header")
    url = str(req.url)
    try:
        validate_dpop_jwt(dpop, "POST", url, expected_jkt)
    except Exception as e:
        raise HTTPException(
            status_code=401, detail="DPoP validation failed"
        ) from e

    return SessionTokenResponse(
        session_token=session_token, expires_at=session.expires_at
    )


@app.get("/api/resource")
async def api_resource(
    session_token: Annotated[SessionToken, Depends(validate_dpop)],
):
    """
    Notes:
    - Can check particular scopes
    """
    session = get_session(session_token)
    if not session:
        raise HTTPException(status_code=400, detail="Session expired")

    return {"user": session.user_name}


@app.post("/auth/logout", status_code=204)
async def auth_logout(req: Request):
    session_token = validate_dpop(req)
    revoke_session(session_token)
    return Response(status_code=204)
