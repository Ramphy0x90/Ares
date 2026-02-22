export const environment = {
    production: false,
    apiUrl: 'http://localhost:8000/api/v1',
    wsUrl: 'ws://localhost:8000/api/v1',
    oidc: {
        authority: 'https://auth.r16a.cloud/application/o/r16a-ares',
        clientId: '8tGA64v5Jk4XmjdzT0s0mrrPYSXCBDKRwCcnDTaR',
        redirectUrl: 'http://localhost:4200/callback',
        postLogoutRedirectUri: 'http://localhost:4200/login',
        scope: 'openid profile email offline_access',
    },
};
