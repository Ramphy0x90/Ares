export const environment = {
    production: false,
    apiUrl: "http://localhost:8000/api/v1",
    wsUrl: "ws://localhost:8000/api/v1",
    oidc: {
        authority: "https://auth.r16a.cloud/application/o/r16a-ares-local",
        clientId: "38tFAsnTCvGpGcRbhYfgFo9hSQD7P2s7EQYTj05A",
        redirectUrl: "http://localhost:4200/callback",
        postLogoutRedirectUri: "http://localhost:4200/login",
        scope: "openid profile email offline_access",
    },
};
