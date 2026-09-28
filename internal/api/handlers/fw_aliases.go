package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// AliasView descreve a representação de um alias (de usuário ou embutido) para a interface.
type AliasView struct {
	ID        string            `json:"id"`
	Nome      string            `json:"nome"`
	Tipo      fwmodel.AliasTipo `json:"tipo"`
	Descricao string            `json:"descricao"`
	NomeChave string            `json:"nome_chave,omitempty"`
	DescChave string            `json:"desc_chave,omitempty"`
	Itens     []string          `json:"itens"`
	Embutido  bool              `json:"embutido"`
	Usos      int               `json:"usos"`
	UsosLista []string          `json:"usos_lista,omitempty"`
}

// GetAliases lista todos os aliases cadastrados (incluindo os embutidos sys:* com seus itens resolvidos).
func (h *FirewallHandler) GetAliases(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.db.CarregarConfigEmEdicao()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	ins, _ := h.fr.Insumos(r.Context())

	// 1. Itens resolvidos dos aliases embutidos
	itensVCN := append([]string{}, ins.RedesVCN...)
	itensVCN = append(itensVCN, cfg.Ajustes.RedesVCNExtras...)
	if itensVCN == nil {
		itensVCN = []string{}
	}

	var itensVPN []string
	if strings.TrimSpace(ins.RedeVPN) != "" {
		itensVPN = []string{ins.RedeVPN}
	} else {
		itensVPN = []string{}
	}

	itensGerencia := make([]string, 0, len(ins.PortasGerencia))
	for _, p := range ins.PortasGerencia {
		itensGerencia = append(itensGerencia, strconv.Itoa(p))
	}

	// 2. Monta embutidos
	embutidos := []AliasView{
		{
			ID:        fwmodel.AliasVCN,
			NomeChave: "fwz.aliases.sys.vcn.nome",
			DescChave: "fwz.aliases.sys.vcn.desc",
			Nome:      "VCN",
			Tipo:      fwmodel.AliasTipoEnderecos,
			Descricao: "Rede da nuvem (VCN) e sub-redes adicionais configuradas",
			Itens:     itensVCN,
			Embutido:  true,
		},
		{
			ID:        fwmodel.AliasVPN,
			NomeChave: "fwz.aliases.sys.vpn.nome",
			DescChave: "fwz.aliases.sys.vpn.desc",
			Nome:      "VPN",
			Tipo:      fwmodel.AliasTipoEnderecos,
			Descricao: "Rede da VPN de acesso remoto WireGuard",
			Itens:     itensVPN,
			Embutido:  true,
		},
		{
			ID:        fwmodel.AliasGerencia,
			NomeChave: "fwz.aliases.sys.gerencia.nome",
			DescChave: "fwz.aliases.sys.gerencia.desc",
			Nome:      "Gerência",
			Tipo:      fwmodel.AliasTipoPortas,
			Descricao: "Portas de gerência do firewall (SSH e painel web)",
			Itens:     itensGerencia,
			Embutido:  true,
		},
	}

	res := make([]AliasView, 0, len(embutidos)+len(cfg.Aliases))
	for _, emb := range embutidos {
		usos, err := h.db.UsosDoAlias(emb.ID)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		emb.Usos = len(usos)
		emb.UsosLista = usos
		res = append(res, emb)
	}

	// 3. Aliases de usuário
	for _, a := range cfg.Aliases {
		usos, err := h.db.UsosDoAlias(a.ID)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		itens := a.Itens
		if itens == nil {
			itens = []string{}
		}
		res = append(res, AliasView{
			ID:        a.ID,
			Nome:      a.Nome,
			Tipo:      a.Tipo,
			Descricao: a.Descricao,
			Itens:     itens,
			Embutido:  false,
			Usos:      len(usos),
			UsosLista: usos,
		})
	}

	writeJSON(w, http.StatusOK, res)
}

// CriarAlias adiciona um novo alias de usuário à configuração em edição.
func (h *FirewallHandler) CriarAlias(w http.ResponseWriter, r *http.Request) {
	var a fwmodel.Alias
	if err := decodeJSON(r, &a); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if strings.HasPrefix(a.ID, "sys:") {
		writeError(w, http.StatusBadRequest, "identificador com prefixo sys: é reservado pelo sistema")
		return
	}
	if strings.TrimSpace(a.Nome) == "" {
		writeError(w, http.StatusBadRequest, "nome do alias é obrigatório")
		return
	}

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.CriarAliasFW(&a)
	}, "alias:"+a.ID)
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.alias.criar", "firewall", a.ID)
	writeJSON(w, http.StatusCreated, a)
}

// AtualizarAlias atualiza um alias de usuário existente.
func (h *FirewallHandler) AtualizarAlias(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id do alias é obrigatório")
		return
	}
	if strings.HasPrefix(id, "sys:") {
		writeError(w, http.StatusBadRequest, "aliases embutidos do sistema não podem ser editados diretamente")
		return
	}

	var a fwmodel.Alias
	if err := decodeJSON(r, &a); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	a.ID = id

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.AtualizarAliasFW(a)
	}, "alias:"+id)
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.alias.alterar", "firewall", id)
	writeJSON(w, http.StatusOK, a)
}

// ApagarAlias remove um alias de usuário, recusando caso esteja em uso em regras ou VPN.
func (h *FirewallHandler) ApagarAlias(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id do alias é obrigatório")
		return
	}
	if strings.HasPrefix(id, "sys:") {
		writeError(w, http.StatusBadRequest, "aliases embutidos do sistema não podem ser excluídos")
		return
	}

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.ApagarAliasFW(id)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.alias.apagar", "firewall", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// PutVCNExtras atualiza a lista de redes extras da VCN nos ajustes do firewall.
func (h *FirewallHandler) PutVCNExtras(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Redes []string `json:"redes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	if body.Redes == nil {
		body.Redes = []string{}
	}

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		cfg, err := db.CarregarConfigEmEdicao()
		if err != nil {
			return err
		}
		novosAjustes := cfg.Ajustes
		novosAjustes.RedesVCNExtras = body.Redes
		return db.SalvarAjustesFW(novosAjustes)
	}, "ajustes")
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.vcn.extras", "firewall", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"redes":  body.Redes,
	})
}
