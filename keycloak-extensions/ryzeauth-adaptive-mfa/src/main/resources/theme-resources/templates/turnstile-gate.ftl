<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
  <#if section = "header">
    ${msg("captchaTitle")}
  <#elseif section = "form">
    <form action="${url.loginAction}" method="post">
      <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}"></div>
      <button type="submit">${msg("doContinue")}</button>
    </form>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  </#if>
</@layout.registrationLayout>
