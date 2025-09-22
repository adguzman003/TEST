#  FrontEnd - Autenticación Híbrida con Microsoft Entra ID (OIDC) y Login Local (Angular + MSAL) 

##  Descripción General

Este módulo implementa un sistema de autenticación híbrido en una aplicación Angular, integrando autenticación por Microsoft Entra ID (mediante OIDC y MSAL) y login local para usuarios tipo "admin". Permite autenticación vía SSO, aprovisionamiento automático desde backend, y protección de rutas en el frontend.

##  Tecnologías Utilizadas

Librerías y servicios clave utilizados en la autenticación

- Angular 15+
- MSAL Angular (`@azure/msal-angular`)
- MSAL Browser (`@azure/msal-browser`)
- Microsoft Entra ID (anteriormente Azure AD)
- Spring Boot (backend)
- JWT local y OIDC token
- Comunicación HTTP segura (`AuthInterceptor`, `ComSegInterceptor`)

---

##  Instalación de dependencias

Comandos necesarios para instalar las librerías MSAL en Angular.

```bash
npm install @azure/msal-angular@^4.0.15 @azure/msal-browser@^4.15.0
```

--- 

##  Configuración del Entorno (environment.ts)

Se agrega el objeto MicrosoftEntraId, con los datos de registros de aplicación proporcionados por el cliente, esto puede variar de acuerdo al ambiente.

```
export const environment = {
  production: true,
  apiUrl: 'https://dsdg-app-renderapp02.davivienda.loc:8003/RenderAppRest',
  MicrosoftEntraId: {
    clientId: 'f0871236-b6c7-4f95-8cb3-2a795227c0e1',
    tenantId: 'd36775fa-f481-4695-86f4-41432c8f57af',
    redirectUri: 'https://dsdg-app-renderapp02.davivienda.loc:8003/RenderApp',
  }
};
```

---

##  Configuración de MSAL (auth/config/auth-config.ts)

Contiene la configuración principal de MSAL, incluyendo authority, cache, scopes y mapas de recursos protegidos.

```
export const msalConfig: Configuration = {
  auth: {
    clientId: environment.MicrosoftEntraId.clientId,
    authority: `https://login.microsoftonline.com/${environment.MicrosoftEntraId.tenantId}`,
    redirectUri: environment.MicrosoftEntraId.redirectUri,
    postLogoutRedirectUri: environment.MicrosoftEntraId.redirectUri
  },
  cache: {
    cacheLocation: 'localStorage',
    storeAuthStateInCookie: true
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message) => console.log(message),
      logLevel: LogLevel.Info,
      piiLoggingEnabled: false
    }
  }
};

export const msalGuardConfig: MsalGuardConfiguration = {
  interactionType: InteractionType.Redirect,
  authRequest: {
    scopes: ['user.read']
  }
};

export const msalInterceptorConfig: MsalInterceptorConfiguration = {
  interactionType: InteractionType.Redirect,
  protectedResourceMap: new Map([
    ['https://graph.microsoft.com/v1.0/me', ['user.read']]
  ])
};
```

---

##  Configuración del AppModule

Se registra e importa todas las dependencias necesarias de MSAL, interceptores y configuraciones para inicializar MSAL correctamente antes del arranque de la app.

```
@NgModule({
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    MsalModule.forRoot(
      MSALInstanceFactory(),
      MSALGuardConfigFactory(),
      MSALInterceptorConfigFactory()
    )
  ],
  providers: [
    { provide: MSAL_INSTANCE, useFactory: MSALInstanceFactory },
    { provide: MSAL_GUARD_CONFIG, useFactory: MSALGuardConfigFactory },
    { provide: MSAL_INTERCEPTOR_CONFIG, useFactory: MSALInterceptorConfigFactory },
    { provide: APP_INITIALIZER, useFactory: initializeMsal, deps: [MSAL_INSTANCE], multi: true },
    MsalService,
    MsalGuard,
    MsalBroadcastService,
    // Interceptors personalizados
    { provide: HTTP_INTERCEPTORS, useClass: ActivityInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptorService, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: ComSegInterceptor, multi: true }
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}

```
---

##  Ruteo y Redirección OIDC (AppRoutingModule)

Se define las rutas de la aplicación, incluyendo la ruta especial /RenderApp para la redirección de Entra ID post login.

```
const routes: Routes = [
  { path: 'RenderApp', component: MsalRedirectComponent },
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  { path: 'login', loadChildren: () => import('./auth/auth.module').then(m => m.AuthModule) },
  {
    path: '',
    loadChildren: () => import('./pages/pages.module').then(m => m.PagesModule),
    canActivate: [authGuard] // Protege rutas internas
  },
  { path: '**', component: NotFoundComponent }
];

```

---

##  Guard de Autenticación (authGuard)

Se mantiene la configuración actual debido que el metodo isAuthenticated controla si el usuario es autenticado por SSO / DB

```
export const authGuard: CanActivateFn = (): Observable<boolean> => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return of(authService.isAuthenticated()).pipe(
    tap(isAuthenticated => {
      if (!isAuthenticated) {
        void router.navigate(['/login']);
      }
    })
  );
};

```

---

##  Servicio de Autenticación (auth.service.ts)

Se agregan y modifican los siguiente metodos para el proceso de autenticación con SSO

```
public loginWithSSO(idToken: string) {
  return this.http.post(`${this.apiUrl}${API_ENDPOINTS.AUTH.OIDCTOKEN}`, { idToken });
}

public setActiveAccount(account: AccountInfo): void {
  this.msalServices.instance.setActiveAccount(account);
}

public getActiveAccount() {
  return this.msalServices.instance.getAllAccounts().length > 0;
}

public isAuthenticated(): boolean {
  const method = localStorage.getItem('authMethod');
  if (method === 'sso') {
    return this.msalServices.instance.getAllAccounts().length > 0;
  }
  return localStorage.getItem('isAuthenticated') === 'true';
}
```

---


##  login.component.ts - Inicialización SSO

Se agrega componente de inicizalización MSAL adicional al AppModule

```
setTimeout(() => 
  (this.msalService.instance as PublicClientApplication).initialize()
    .then(() => {
      console.log("MSAL inicializado desde login.component");
      this.handleSSOLogin();
    })
    .catch(err => {
      console.error("Error inicializando MSAL en login:", err);
      this.errorMessage = 'Error al inicializar autenticación SSO.';
    }), 0
);
```

---


##  Flujo de Autenticación (SSO)

1. Usuario accede al login
2. Ingresa su loginId
3. Se consulta al backend (/auth/method) si es local o SSO
4. Si es SSO:
   - 4.1 Redirige a Entra ID con MSAL
   - 4.2 Obtiene ID Token tras autenticación
   - 4.3 Envia el token a /auth/oidc-token (backend)
   - 4.4 Backend valida token y crea/actualiza usuario
   - 4.5 Se almacena JWT + datos del usuario

---

##  Consideraciones de Seguridad

 - Almacén de sesión: localStorage + sessionStorage
 - JWT del backend protegido en sesión
 - Uso de MSAL para manejo seguro de tokens OIDC
 - Protección de rutas vía authGuard

---

##  Logout

Se modifica evento Logout de acuerdo al tipo de autenticación cierre sesión segun corresponda.

```

   public async logout(): Promise<void> {
    try {
      const isSsoUser = localStorage.getItem('authMethod') === 'sso';
      if(isSsoUser){
        console.log('********>Ingresa logout: ', isSsoUser);
        localStorage.removeItem('authMethod');
        localStorage.removeItem('isAuthenticated');
        localStorage.removeItem('userData');
        localStorage.removeItem('currentUserId');
        this.msalInstance.logout();
      } else {
        await this.authService.logout();
      }
      await Swal.fire({
        position: 'center',
        icon: 'success',
        title: 'Sesión cerrada correctamente',
        showConfirmButton: false,
        timer: 5000
      });
      
    } catch (error) {
      // Maneja el error si la promesa falla
      this.loggerService.error('Error cerrando sesión:', error);
    }
  }  
```

---

###  Referencias

Fuentes:

Angular SPA
Angular single-page application using MSAL Angular to sign-in users against Microsoft Entra External ID - Code Samples | Microsoft Learn: https://learn.microsoft.com/en-us/samples/azure-samples/ms-identity-ciam-javascript-tutorial/ms-identity-ciam-javascript-tutorial-2-sign-in-angular/

Lbrary Msal
microsoft-authentication-library-for-js/lib/msal-angular at dev · AzureAD/microsoft-authentication-library-for-js · GitHub: https://github.com/AzureAD/microsoft-authentication-library-for-js/tree/dev/lib/msal-angular
