# Reproducible terminal demo: one shared provider key, one revocable key per
# teammate, and a limit that actually bites.
#
#   ./docs/demo-setup.sh     # stack + an "alice" tenant at 3 requests/60s
#   vhs docs/demo.tape       # regenerates docs/demo.gif

Output docs/demo.gif

Set Shell zsh
Set FontSize 16
Set Width 1200
Set Height 640
Set Padding 20
Set Theme "Builtin Dark"
Set TypingSpeed 20ms

Hide
Type "clear" Enter
# Non-interactive zsh does not treat a leading # as a comment, and would try to
# glob the ? in a narration line, so both are turned on before recording.
Type "setopt interactive_comments" Enter
Type "export TG=http://localhost:8080 ADMIN='demo-admin-token-0123456789'" Enter
Type "clear" Enter
Show

Sleep 600ms

Type "# The team's shared provider key lives only in the gateway's environment."
Enter
Sleep 800ms
Type "# Alice never sees it. She gets her own key, with her own budget."
Enter
Sleep 1300ms

Type `KEY=$(curl -s -X POST $TG/_admin/api/tenants/alice/keys -H "Authorization: Bearer $ADMIN" -d '{}' | jq -r .key)`
Enter
Sleep 1500ms
Type "echo $KEY"
Enter
Sleep 1800ms

Type "# She points her SDK at the gateway with that key. What reaches the provider?"
Enter
Sleep 1200ms
Type `curl -s -H "X-API-Key: $KEY" $TG/anthropic/v1/messages | jq '{tenant, headers}'`
Enter
Sleep 3200ms

Type "# Her key was stripped; the shared credential was attached on the way out."
Enter
Sleep 2200ms
Type "clear" Enter
Sleep 500ms

Type "# Her budget is 3 requests a minute. Now her agent loop runs away."
Enter
Sleep 1300ms
Type `for i in 1 2 3 4; do printf "request $i -> "; curl -s -o /dev/null -w "%{http_code}\n" -H "X-API-Key: $KEY" $TG/anthropic/v1/messages; done`
Enter
Sleep 3800ms

Type "# She gets the 429s. Nobody else's budget moved, and the key still works."
Enter
Sleep 2600ms
