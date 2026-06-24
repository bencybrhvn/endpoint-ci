// Package prefilter provides an Aho-Corasick multi-literal matcher used to
// decide, in a single pass, which literal-anchored detectors can possibly match
// a buffer (so the rest are skipped). This is the cheap "multi-pattern matcher"
// front end to the regex detectors.
package prefilter

type node struct {
	next map[byte]int
	fail int
	out  []int // pattern indices ending at this node (incl. via fail links)
}

type Matcher struct {
	nodes []node
	pats  []string
}

// New builds an Aho-Corasick automaton over the given literal patterns.
func New(pats []string) *Matcher {
	m := &Matcher{pats: pats}
	m.nodes = []node{{next: map[byte]int{}}}
	for pi, p := range pats {
		cur := 0
		for i := 0; i < len(p); i++ {
			b := p[i]
			nx, ok := m.nodes[cur].next[b]
			if !ok {
				nx = len(m.nodes)
				m.nodes = append(m.nodes, node{next: map[byte]int{}})
				m.nodes[cur].next[b] = nx
			}
			cur = nx
		}
		m.nodes[cur].out = append(m.nodes[cur].out, pi)
	}
	// BFS to set fail links and merge outputs.
	var queue []int
	for _, nx := range m.nodes[0].next {
		queue = append(queue, nx)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for b, nx := range m.nodes[cur].next {
			queue = append(queue, nx)
			f := m.nodes[cur].fail
			for f != 0 {
				if _, ok := m.nodes[f].next[b]; ok {
					break
				}
				f = m.nodes[f].fail
			}
			if fn, ok := m.nodes[f].next[b]; ok && fn != nx {
				m.nodes[nx].fail = fn
			} else {
				m.nodes[nx].fail = 0
			}
			m.nodes[nx].out = append(m.nodes[nx].out, m.nodes[m.nodes[nx].fail].out...)
		}
	}
	return m
}

// Present returns a bool per pattern index: true if that literal occurs in text.
// One O(len(text)) pass for all patterns.
func (m *Matcher) Present(text string) []bool {
	present := make([]bool, len(m.pats))
	cur := 0
	for i := 0; i < len(text); i++ {
		b := text[i]
		for cur != 0 {
			if _, ok := m.nodes[cur].next[b]; ok {
				break
			}
			cur = m.nodes[cur].fail
		}
		if nx, ok := m.nodes[cur].next[b]; ok {
			cur = nx
		} else {
			cur = 0
		}
		for _, pi := range m.nodes[cur].out {
			present[pi] = true
		}
	}
	return present
}
