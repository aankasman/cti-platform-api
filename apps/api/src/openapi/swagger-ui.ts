/**
 * Swagger UI HTML Generator
 * 
 * Premium API documentation using Swagger UI 3.x + Flattop theme.
 * Clean light mode with Rinjani Analytics branding.
 */

import { openApiSpec } from './spec';

// ============================================================================
// HTML GENERATOR
// ============================================================================
export function getSwaggerUIHTML(specUrl: string = '/api-docs/openapi.json'): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RinjaniAnalytics CTI API — Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css">
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-themes@3.0.1/themes/3.x/theme-flattop.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        /* =======================================================
           1. GLOBAL RESET
           ======================================================= */
        *, *::before, *::after { box-sizing: border-box; }
        html { overflow-x: hidden; }
        body {
            margin: 0; padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            -webkit-font-smoothing: antialiased;
            overflow-x: hidden;
        }

        /* =======================================================
           2. SWAGGER CONTAINMENT
           ======================================================= */
        #swagger-ui, .swagger-ui {
            font-family: 'Inter', sans-serif !important;
        }
        .swagger-ui .wrapper {
            max-width: 1240px;
            margin: 0 auto;
            padding: 0 24px;
        }

        /* =======================================================
           3. TOPBAR — dark gradient header with Rinjani branding
           ======================================================= */
        .swagger-ui .topbar {
            background: linear-gradient(135deg, #0f172a, #1e293b) !important;
            border-bottom: none !important;
            padding: 14px 24px !important;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .swagger-ui .topbar .wrapper { max-width: 1240px; margin: 0 auto; padding: 0; }
        .swagger-ui .topbar .topbar-wrapper { justify-content: flex-start; align-items: center; gap: 24px; }
        .swagger-ui .topbar .topbar-wrapper img[alt="Swagger UI"],
        .swagger-ui .topbar .topbar-wrapper > .link { display: none !important; }

        /* Topbar explore/download bar */
        .swagger-ui .topbar .download-url-wrapper {
            display: flex; align-items: center; gap: 8px;
        }
        .swagger-ui .topbar .download-url-wrapper input[type="text"] {
            background: #fff !important; color: #1e293b !important;
            border: 1px solid #475569 !important; border-radius: 6px !important;
            padding: 6px 12px !important; font-size: 0.85rem !important;
        }
        .swagger-ui .topbar .download-url-wrapper .download-url-button {
            background: #16a34a !important; color: #fff !important;
            border: none !important; border-radius: 6px !important;
            padding: 6px 16px !important; font-weight: 600 !important;
            cursor: pointer !important;
        }
        .swagger-ui .topbar .download-url-wrapper .download-url-button:hover {
            background: #15803d !important;
        }

        /* =======================================================
           4. INFO HEADER
           ======================================================= */
        .swagger-ui .info { margin: 28px 0 16px 0 !important; }
        .swagger-ui .info hgroup.main .title {
            font-family: 'Inter', sans-serif !important;
            font-weight: 800 !important; font-size: 1.6rem !important;
            color: #0f172a !important;
        }
        .swagger-ui .info .description p {
            color: #475569 !important; font-size: 0.92rem !important;
            line-height: 1.65 !important; margin-top: 6px !important;
        }
        .swagger-ui .info a { color: #2563eb !important; text-decoration: none !important; }
        .swagger-ui .info a:hover { text-decoration: underline !important; }

        /* =======================================================
           5. OP BLOCKS — custom method colors
           ======================================================= */
        .swagger-ui .opblock {
            border-radius: 8px !important;
            margin-bottom: 8px !important;
            box-shadow: 0 1px 3px rgba(0,0,0,.04) !important;
        }
        .swagger-ui .opblock .opblock-summary-method {
            font-family: 'JetBrains Mono', monospace !important;
            font-weight: 700 !important; font-size: 0.75rem !important;
            padding: 5px 10px !important; border-radius: 4px !important;
            min-width: 60px; text-align: center;
        }
        .swagger-ui .opblock .opblock-summary-path {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.85rem !important; font-weight: 600 !important;
        }
        .swagger-ui .opblock .opblock-summary-description {
            font-size: 0.82rem !important; color: #64748b !important;
        }

        /* =======================================================
           6. PARAMETERS
           ======================================================= */
        .swagger-ui .parameters-col_description input,
        .swagger-ui .parameters-col_description select,
        .swagger-ui .parameters-col_description textarea {
            font-family: 'JetBrains Mono', monospace !important;
        }
        .swagger-ui .parameter__name { font-weight: 600 !important; }
        .swagger-ui .parameter__type { font-size: 0.8rem !important; }

        /* =======================================================
           7. BUTTONS
           ======================================================= */
        .swagger-ui .btn {
            border-radius: 6px !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 600 !important;
            transition: all 0.15s ease !important;
        }
        .swagger-ui .btn.execute {
            background: #16a34a !important; color: #fff !important;
            border: none !important; padding: 10px 24px !important;
        }
        .swagger-ui .btn.execute:hover { background: #15803d !important; }
        .swagger-ui .btn.authorize {
            background: #2563eb !important; color: #fff !important;
            border: none !important; border-radius: 6px !important;
            padding: 8px 18px !important;
        }
        .swagger-ui .btn.authorize:hover { background: #1d4ed8 !important; }
        .swagger-ui .btn.authorize svg { fill: #fff !important; }

        /* =======================================================
           8. CODE BLOCKS
           ======================================================= */
        .swagger-ui .opblock-body pre,
        .swagger-ui .microlight,
        .swagger-ui .highlight-code pre {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.8rem !important; line-height: 1.6 !important;
            border-radius: 6px !important;
        }
        .swagger-ui code {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.82em !important;
        }

        /* =======================================================
           9. MODELS / SCHEMAS
           ======================================================= */
        .swagger-ui section.models {
            border-radius: 8px !important;
        }
        .swagger-ui section.models h4 {
            font-family: 'Inter', sans-serif !important;
            font-weight: 700 !important;
        }

        /* =======================================================
           10. AUTHORIZATION MODAL
           ======================================================= */
        .swagger-ui .dialog-ux .modal-ux {
            border-radius: 12px !important;
            box-shadow: 0 20px 60px rgba(0,0,0,.15) !important;
        }
        .swagger-ui .dialog-ux .modal-ux-header h3 {
            font-family: 'Inter', sans-serif !important;
            font-weight: 700 !important;
        }

        /* =======================================================
           11. SCROLLBAR
           ======================================================= */
        ::-webkit-scrollbar { width: 7px; height: 7px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; border-radius: 4px; }
        ::-webkit-scrollbar-thumb { background: #94a3b8; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #64748b; }

        /* =======================================================
           12. RESPONSIVE
           ======================================================= */
        @media (max-width: 768px) {
            .swagger-ui .wrapper { padding: 0 12px; }
            .swagger-ui .opblock-body { padding: 10px !important; }
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>

    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-standalone-preset.js"></script>
    <script>
    window.onload = function() {
        window.ui = SwaggerUIBundle({
            url: "${specUrl}",
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
            plugins: [SwaggerUIBundle.plugins.DownloadUrl],
            layout: 'StandaloneLayout',
            docExpansion: 'list',
            filter: true,
            tryItOutEnabled: true,
            persistAuthorization: true,
            defaultModelsExpandDepth: 1,
            defaultModelExpandDepth: 2,
            syntaxHighlight: { activated: true, theme: "agate" }
        });

        // Inject Rinjani branding into topbar
        setTimeout(function() {
            var tw = document.querySelector('.topbar-wrapper');
            if (!tw) return;

            var link = tw.querySelector('a');
            if (link) link.style.display = 'none';

            var brand = document.createElement('div');
            brand.style.cssText = 'display:flex;align-items:center;gap:20px;';

            var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('width', '30');
            svg.setAttribute('height', '30');
            svg.setAttribute('viewBox', '0 0 500 500');
            svg.innerHTML = '<g transform="matrix(5.804251,0.05161894,-0.06174394,6.9589776,-114.66292,-662.73691)" style="fill:#00d4aa"><path d="m 18.554538,150.48551 c -0.158474,-14.75575 -0.316945,-29.51117 10.95595,-29.78142 11.272894,-0.27025 33.975771,13.94442 45.243999,13.8386 11.268228,-0.10583 11.100442,-14.53243 10.932653,-28.95932" transform="matrix(1.0442053,7.9087599e-5,1.1342088e-4,1.0548666,2.794921,0.76917208)"/><path d="m 18.554538,150.48551 c -0.158474,-14.75575 -0.316945,-29.51117 10.95595,-29.78142 11.272894,-0.27025 33.975771,13.94442 45.243999,13.8386 11.268228,-0.10583 11.100442,-14.53243 10.932653,-28.95932" transform="matrix(1.0442053,7.9087599e-5,1.1342088e-4,1.0548666,16.361549,-8.3967354)"/></g>';

            var title = document.createElement('span');
            title.textContent = 'Rinjani Analytics';
            title.style.cssText = 'color:#e2e8f0;font-size:1.2rem;font-weight:700;letter-spacing:-0.02em;font-family:Inter,sans-serif;';

            brand.appendChild(svg);
            brand.appendChild(title);
            tw.insertBefore(brand, tw.firstChild);
        }, 800);
    };
    </script>
</body>
</html>`;
}

// ============================================================================
// OPENAPI SPEC GETTER
// ============================================================================
export function getOpenAPISpec() {
    return openApiSpec;
}
