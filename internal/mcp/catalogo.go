package mcp

// catalogo é a lista COMPLETA de tools deste binário, antes de qualquer
// filtragem por policy.
//
// Ela é uma função e não uma var de pacote porque `Registry` a ORDENA, e
// ordenar uma var global embaralharia a lista para todos os chamadores
// seguintes — inclusive entre dois testes do mesmo pacote.
func catalogo() []Ferramenta {
	return []Ferramenta{
		toolStatus,
		toolSnapshotList,
		toolSnapshotInfo,
		toolSnapshotCompare,
		toolHostOverview,
		toolChecksCatalog,
		toolFindingsList,
		toolFindingGet,
		toolFindingsCorrelate,
		toolCoverageGet,
		toolProcessCensus,
		toolProcessGet,
		toolProcessTree,
		toolNetCensus,
		toolNetIP,
		toolNetPort,
		toolFileInspect,
	}
}
