#!/usr/bin/env bash
# Supabase + Google OAuth Setup Helper (Bash version)

set -euo pipefail

normalize_host() {
  local h="$1"
  h="$(echo "$h" | xargs)"   # trim
  if [[ -z "$h" ]]; then echo ""; return; fi
  if [[ "$h" != http*://* ]]; then h="https://$h"; fi
  # strip trailing slashes
  echo "${h%%/}"
}

# ---- prompts ----
echo ""
echo "🧭 Supabase + Google OAuth Setup Helper"
echo ""

read -rp "Google Project Name (as shown in Google Cloud Console, used in links): " googleProjectName

echo ""
echo "➡️  Enter your Supabase Project ID."
echo "   Find it here: https://supabase.com/dashboard → your Project → Project Settings → Project ID"
echo ""
read -rp "Supabase Project ID: " projectId

projectId=$(echo "$projectId" | tr '[:upper:]' '[:lower:]')

read -rp "Supabase 'Site URL' (Default http://192.168.2.203:5173): " siteUrlRaw
siteUrl=$(normalize_host "$siteUrlRaw")

read -rp "(OPTIONAL) Enter additional app domain(s) (comma-separated). At least set ${projectId}.supabase.co. (Will be added to Authorized domains (https://console.cloud.google.com/auth/branding?project=${googleProjectName})): " domainsRaw
IFS=',' read -ra domainsArr <<<"$domainsRaw"

domainList=()
for d in "${domainsArr[@]}"; do
  dd=$(normalize_host "$d")
  [[ -n "$dd" ]] && domainList+=("$dd")
done
# always include projectId.supabase.co
if [[ ! " ${domainList[*]} " =~ "${projectId}.supabase.co" ]]; then
  domainList+=("https://${projectId}.supabase.co")
fi

read -rp "Include localhost dev URLs (http://localhost:3000)? [Y/n]: " includeLocalhost
includeLocalhost=${includeLocalhost,,} # lowercase
wantLocal=true
if [[ "$includeLocalhost" == "n" ]]; then wantLocal=false; fi

read -rp "Enter any custom LAN dev URLs (comma-separated) like http://192.168.2.503:5173, or leave blank: " lanRaw
IFS=',' read -ra lanArr <<<"$lanRaw"

lanList=()
for l in "${lanArr[@]}"; do
  ll=$(normalize_host "$l")
  [[ -n "$ll" ]] && lanList+=("$ll")
done

# ---- derived values ----
projectUrl="https://${projectId}.supabase.co"
supabaseGoogleProviderUrl="https://supabase.com/dashboard/project/${projectId}/auth/providers?provider=Google"
googleCredentialsUrl="https://console.cloud.google.com/apis/credentials?project=${googleProjectName}"
googleConsentUrl="https://console.cloud.google.com/apis/credentials/consent?project=${googleProjectName}"
googleOidcScopesUrl="https://console.cloud.google.com/auth/scopes?project=${googleProjectName}"
googleBrandingUrl="https://console.cloud.google.com/auth/branding?project=${googleProjectName}"
googleClientsUrl="https://console.cloud.google.com/auth/clients?project=${googleProjectName}"

# branding authorized domains
brandingHosts=("$(echo "$projectUrl" | awk -F/ '{print $3}')")
for d in "${domainList[@]}"; do
  brandingHosts+=("$(echo "$d" | awk -F/ '{print $3}')")
done

# consent authorized domains (base domains)
consentDomains=("supabase.co")

# ---- output ----
echo ""
echo "======================== SETUP SUMMARY ========================"
echo ""
echo "Google Project (visit all):"
echo "  • Credentials:    $googleCredentialsUrl"
echo "  • Consent screen: $googleConsentUrl"
echo "  • OIDC Scopes:    $googleOidcScopesUrl"
echo "  • Branding:       $googleBrandingUrl"
echo ""
echo "Supabase Project (visit all):"
echo "  • URL configuration: https://supabase.com/dashboard/project/${projectId}/auth/url-configuration"
echo "  • Providers:         https://supabase.com/dashboard/project/${projectId}/auth/providers"
echo "  • Google provider:   $supabaseGoogleProviderUrl"
echo ""
echo "Your Supabase identifiers:"
echo "  • Project ID:  $projectId"
echo "  • Project URL: $projectUrl"
[[ -n "$siteUrl" ]] && echo "  • (Dev) Site URL: $siteUrl"
echo ""
echo "Google Branding Authorized domains ($googleBrandingUrl):"
for h in "${brandingHosts[@]}"; do
  echo "    • $h"
done
echo ""
echo "Google OAuth 2.0 Client (Web application) (visit $googleClientsUrl):"
echo "  Authorized JavaScript origins:"
echo "    • $projectUrl"
if $wantLocal; then
  echo "    • http://localhost:3000"
fi
echo ""
echo "  Authorized Redirect URIs:"
echo "    • ${projectUrl}/auth/v1/callback"
echo "    • ${projectUrl}"
if $wantLocal; then
  echo "    • http://localhost:3000/auth/callback"
fi
echo ""
echo "IMPORTANT:"
echo "  • Add your **Project URL** to BOTH lists above."
echo "  • Ensure ${projectUrl}/auth/v1/callback is included in Authorized Redirect URIs."
echo "    Confirm in Supabase → Google provider page: $supabaseGoogleProviderUrl"
echo "  • Once your OAuth 2.0 Client is created, copy the Client ID and Secret into Supabase."
echo ""
echo "OAuth Consent Screen → Authorized domains:"
for d in "${consentDomains[@]}"; do
  echo "    • $d"
done
echo ""
echo "Supabase → Authentication → Providers → Google:"
echo "  • Toggle ON Google provider."
echo "  • Paste the Client ID and Client Secret from Google Credentials."
echo "  • Scopes (explicit): openid email profile"
echo ""
echo "Google OIDC Scopes workflow (visit $googleOidcScopesUrl):"
echo "  • Add: openid, userinfo.email, userinfo.profile"
echo ""
echo "==============================================================="
