from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from core.utils.graph import list_user_authentication_methods

def home(request):
    return render(request, "core/home.html")


def prettify_auth_methods(methods):
    pretty = []

    for method in methods:
        odata_type = method.get("@odata.type", "")
        label = "Unknown method"
        details = ""

        if odata_type.endswith("passwordAuthenticationMethod"):
            label = "Password"
            created = method.get("createdDateTime")
            if created:
                details = f"Created: {created}"

        elif odata_type.endswith("phoneAuthenticationMethod"):
            label = "Phone"
            phone_type = method.get("phoneType", "")
            phone_number = method.get("phoneNumber", "")
            details = f"{phone_type}: {phone_number}"

        elif odata_type.endswith("softwareOathAuthenticationMethod"):
            label = "Software OATH token"

        elif odata_type.endswith("windowsHelloForBusinessAuthenticationMethod"):
            label = "Windows Hello for Business"
            display_name = method.get("displayName") or "Unnamed device"
            created = method.get("createdDateTime", "")
            details = f"{display_name} (created {created})"

        else:
            details = str(method)

        pretty.append(
            {
                "label": label,
                "details": details,
                "id": method.get("id", ""),
                "type": odata_type,
            }
        )

    return pretty


@login_required
def profile(request):
    attributes = request.session.get("attributes", {})
    auth_methods = []
    graph_error = None

    try:
        username = request.user.username.strip().lower()
        if "@" not in username:
            username = f"{username}@dtu.dk"

        raw_methods = list_user_authentication_methods(username)
        auth_methods = prettify_auth_methods(raw_methods)
    except Exception as exc:
        graph_error = str(exc)
        username = request.user.username

    return render(
        request,
        "core/profile.html",
        {
            "cas_attributes": attributes,
            "resolved_upn": username,
            "auth_methods": auth_methods,
            "graph_error": graph_error,
        },
    )
