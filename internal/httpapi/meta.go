package httpapi

import (
	"net/http"

	"github.com/Arequ/mission-control/internal/configrepo"
)

type serverMeta struct {
	ConfigRepo   string            `json:"config_repo"`
	ConfigBranch string            `json:"config_branch"`
	ConfigLinks  map[string]string `json:"config_links"`
	BreakGlass   bool              `json:"break_glass"`
	SSOEnabled   bool              `json:"sso_enabled"`
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	repo := s.configRepo
	if repo.Slug == "" {
		repo = configrepo.Default()
	}
	links := make(map[string]string, len(configrepo.Kinds()))
	for _, kind := range configrepo.Kinds() {
		link, err := configrepo.ProposeURL(repo, kind)
		if err != nil {
			s.log.Error("config link", "kind", kind, "err", err)
			continue
		}
		links[string(kind)] = link
	}
	ssoOn := false
	if s.store != nil {
		if items, err := s.store.ListEnabledSSOProviders(r.Context()); err == nil && len(items) > 0 {
			ssoOn = true
		}
	}
	writeJSON(w, http.StatusOK, serverMeta{
		ConfigRepo:   repo.Slug,
		ConfigBranch: repo.Branch,
		ConfigLinks:  links,
		BreakGlass:   s.breakGlass,
		SSOEnabled:   ssoOn,
	})
}
