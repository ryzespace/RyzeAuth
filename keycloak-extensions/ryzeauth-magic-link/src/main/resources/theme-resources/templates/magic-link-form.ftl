<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
  <#if section = "header">
    ${msg("magicLinkTitle")}
  <#elseif section = "form">
    <form action="${url.loginAction}" method="post">
      <button type="submit" name="submitAction" value="confirm">${msg("magicLinkCheck")}</button>
      <button type="submit" name="submitAction" value="resend">${msg("magicLinkResend")}</button>
    </form>
  </#if>
</@layout.registrationLayout>
