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

        elif odata_type.endswith("microsoftAuthenticatorAuthenticationMethod"):
            label = "Microsoft Authenticator"
            display_name = method.get("displayName", "")
            device_tag = method.get("deviceTag", "")
            details = f"{display_name} ({device_tag})"

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

