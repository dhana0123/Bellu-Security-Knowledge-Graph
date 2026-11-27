package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Fuzzy candidate generation is opt-in and bounded:
//   - records are blocked by affected package name, so only records sharing a package are compared;
//   - a block of at most fuzzyBlockCap records is compared pairwise;
//   - a larger block is sorted by a MinHash-like signature (its two smallest token hashes) and
//     each record is compared only with the next fuzzyWindow records, so work is
//     O(block size * fuzzyWindow) instead of O(block size squared);
//   - at most fuzzyMaxCandidates pairs are kept (blocks are visited in sorted order, so the cut
//     is deterministic).
const (
	fuzzyBlockCap      = 200
	fuzzyWindow        = 25
	fuzzyMaxCandidates = 1_000_000
)

var tokenSplit = regexp.MustCompile(`[^\p{L}\p{N}]+`)

func hashToken(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// fuzzyFeatures extracts the sorted token-hash set of the summary and the affected package
// names from a stored record body. Unparseable bodies yield no features.
func fuzzyFeatures(body []byte) ([]uint32, []string) {
	var rec model.Record
	if json.Unmarshal(body, &rec) != nil {
		return nil, nil
	}
	set := map[uint32]struct{}{}
	for _, t := range tokenSplit.Split(strings.ToLower(rec.Summary), -1) {
		if t != "" {
			set[hashToken(t)] = struct{}{}
		}
	}
	toks := make([]uint32, 0, len(set))
	for h := range set {
		toks = append(toks, h)
	}
	slices.Sort(toks)
	pk := map[string]bool{}
	for _, a := range rec.Affected {
		if a.Kind == "package" || a.Kind == "" {
			if n := strings.ToLower(strings.TrimSpace(a.Name)); n != "" {
				pk[n] = true
			}
		}
	}
	var pkgs []string
	for n := range pk {
		pkgs = append(pkgs, n)
	}
	sort.Strings(pkgs)
	return toks, pkgs
}

// jaccard of two sorted unique hash slices.
func jaccard(a, b []uint32) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	i, j, inter := 0, 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			inter++
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return float64(inter) / float64(len(a)+len(b)-inter)
}

func sig(t []uint32) [2]uint32 {
	s := [2]uint32{^uint32(0), ^uint32(0)}
	if len(t) > 0 {
		s[0] = t[0]
	}
	if len(t) > 1 {
		s[1] = t[1]
	}
	return s
}

// fuzzyCandidates returns candidate pairs of records that share no group, share a package name,
// and have summary similarity >= the threshold. It streams record bodies once and keeps only
// token hashes and package names.
func (s *Store) fuzzyCandidates(ctx context.Context, sv *solved, opts ResolveOptions) (map[[2]string]float64, int, error) {
	th := opts.FuzzyThreshold
	if th <= 0 || th > 1 {
		th = 0.8
	}
	g := sv.g
	pos := make(map[uint64]int32, g.records())
	for r := int32(0); r < int32(g.records()); r++ {
		pos[uint64(g.recSrc[r])<<32|uint64(uint32(g.recExt[r]))] = r
	}
	comps := make([][]int32, g.records())
	for _, m := range sv.members {
		comps[m.rec] = append(comps[m.rec], m.comp)
	}
	toks := make([][]uint32, g.records())
	blocks := map[string][]int32{}

	rows, err := s.DB.QueryContext(ctx, `SELECT source, external_id, json FROM source_record ORDER BY source, external_id`)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var src, ext string
		var body []byte
		if err := rows.Scan(&src, &ext, &body); err != nil {
			rows.Close()
			return nil, 0, err
		}
		si, ok := g.srcIdx[src]
		if !ok {
			continue
		}
		ei, ok := g.idx[ext]
		if !ok {
			continue
		}
		r, ok := pos[uint64(si)<<32|uint64(uint32(ei))]
		if !ok || len(comps[r]) == 0 {
			continue
		}
		t, pkgs := fuzzyFeatures(body)
		if len(t) == 0 {
			continue
		}
		toks[r] = t
		for _, p := range pkgs {
			blocks[p] = append(blocks[p], r)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	out := map[[2]string]float64{}
	share := func(a, b int32) bool {
		for _, x := range comps[a] {
			if slices.Contains(comps[b], x) {
				return true
			}
		}
		return false
	}
	comparisons := 0
	compare := func(a, b int32) {
		if a == b || share(a, b) {
			return
		}
		comparisons++
		if sc := jaccard(toks[a], toks[b]); sc >= th {
			l, r := g.recKey(a), g.recKey(b)
			if r < l {
				l, r = r, l
			}
			out[[2]string{l, r}] = sc
		}
	}
	pkgNames := make([]string, 0, len(blocks))
	for p := range blocks {
		pkgNames = append(pkgNames, p)
	}
	sort.Strings(pkgNames)
	for _, p := range pkgNames {
		if len(out) >= fuzzyMaxCandidates {
			break
		}
		m := blocks[p]
		if len(m) <= fuzzyBlockCap {
			for x := 0; x < len(m); x++ {
				for y := x + 1; y < len(m); y++ {
					compare(m[x], m[y])
				}
			}
			continue
		}
		slices.SortFunc(m, func(a, b int32) int {
			sa, sb := sig(toks[a]), sig(toks[b])
			switch {
			case sa[0] != sb[0]:
				if sa[0] < sb[0] {
					return -1
				}
				return 1
			case sa[1] != sb[1]:
				if sa[1] < sb[1] {
					return -1
				}
				return 1
			}
			return int(a - b)
		})
		for x := 0; x < len(m); x++ {
			for y := x + 1; y < len(m) && y <= x+fuzzyWindow; y++ {
				compare(m[x], m[y])
			}
		}
	}
	return out, comparisons, nil
}

// applyCandidates reconciles candidate_pair to exactly want.
func (s *Store) applyCandidates(ctx context.Context, want map[[2]string]float64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	have := map[[2]string]float64{}
	rows, err := tx.QueryContext(ctx, `SELECT left_id, right_id, score FROM candidate_pair`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k [2]string
		var sc sql.NullFloat64
		if err := rows.Scan(&k[0], &k[1], &sc); err != nil {
			rows.Close()
			return err
		}
		have[k] = sc.Float64
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for k, sc := range have {
		if w, ok := want[k]; !ok || w != sc {
			if _, err := tx.ExecContext(ctx, `DELETE FROM candidate_pair WHERE left_id=? AND right_id=?`, k[0], k[1]); err != nil {
				return err
			}
			delete(have, k)
		}
	}
	for k, sc := range want {
		if _, ok := have[k]; !ok {
			if _, err := tx.ExecContext(ctx, `INSERT INTO candidate_pair(left_id, right_id, score) VALUES(?,?,?)`, k[0], k[1], sc); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
