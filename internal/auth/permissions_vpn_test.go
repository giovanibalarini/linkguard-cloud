package auth

import "testing"

func TestVPNPermissionsAreCataloguedAndNotGrantedToNonAdminDefaults(t *testing.T) {
	for _, p := range []Permission{PermVPNRead, PermVPNWrite, PermVPNEnroll} {
		if !IsValidPermission(string(p)) {
			t.Errorf("VPN permission %q is not assignable through the catalog", p)
		}
	}
	for _, role := range DefaultRoles {
		// O admin tem tudo; o "Usuário VPN" existe justamente para a VPN e é
		// conferido à parte, abaixo.
		if role.ID == "role-admin" || role.ID == "role-vpn-user" {
			continue
		}
		for _, got := range role.Permissions {
			if got == PermVPNRead || got == PermVPNWrite || got == PermVPNEnroll {
				t.Errorf("existing default role %q gained sensitive VPN permission %q", role.Name, got)
			}
		}
	}
}

// O papel de quem só usa a VPN não pode crescer: qualquer permissão a mais
// chegaria em silêncio a todo mundo que já o tem.
func TestUsuarioVPNSoUsaAPropriaVPN(t *testing.T) {
	for _, role := range DefaultRoles {
		if role.ID != "role-vpn-user" {
			continue
		}
		if len(role.Permissions) != 1 || role.Permissions[0] != PermVPNEnroll {
			t.Fatalf("o papel Usuário VPN tem %v; queria só %q", role.Permissions, PermVPNEnroll)
		}
		return
	}
	t.Fatal("o papel pronto Usuário VPN não existe")
}
