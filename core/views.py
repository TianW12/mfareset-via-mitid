from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from core.utils.graph import list_user_authentication_methods
from core.utils.auth_methods import prettify_auth_methods

def home(request):
    if request.user.is_authenticated:
        return redirect("profile")
    return render(request, "core/home.html")


@login_required
def profile(request):
    attributes = request.session.get("attributes", {})
    auth_methods = []
    graph_error = None

    username = request.user.username.strip().lower()
    if "@" not in username:
        username = f"{username}@dtu.dk"

    try:
        raw_methods = list_user_authentication_methods(username)
        auth_methods = prettify_auth_methods(raw_methods)
    except Exception as exc:
        graph_error = str(exc)

    has_resettable_methods = any(
        not m["type"].endswith("passwordAuthenticationMethod")
        for m in auth_methods
    )

    return render(
        request,
        "core/profile.html",
        {
            "cas_attributes": attributes,
            "resolved_upn": username,
            "auth_methods": auth_methods,
            "graph_error": graph_error,
            "has_resettable_methods": has_resettable_methods,
        },
    )
