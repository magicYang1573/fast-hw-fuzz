// -*- mode: C++; c-file-style: "cc-mode" -*-
//*************************************************************************
// DESCRIPTION: Verilator: Graph optimizations
//
// Code available from: https://verilator.org
//
//*************************************************************************
//
// Copyright 2003-2024 by Wilson Snyder. This program is free software; you
// can redistribute it and/or modify it under the terms of either the GNU
// Lesser General Public License Version 3 or the Perl Artistic License
// Version 2.0.
// SPDX-License-Identifier: LGPL-3.0-only OR Artistic-2.0
//
//*************************************************************************

#define VL_MT_DISABLED_CODE_UNIT 1

#include "config_build.h"
#include "verilatedos.h"

#include "V3Graph.h"

#include "V3File.h"
#include "V3Global.h"

#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

VL_DEFINE_DEBUG_FUNCTIONS;

//######################################################################
//######################################################################
// Vertices

V3GraphVertex::V3GraphVertex(V3Graph* graphp, const V3GraphVertex& old)
    : m_fanout{old.m_fanout}
    , m_color{old.m_color}
    , m_rank{old.m_rank} {
    m_userp = nullptr;
    verticesPushBack(graphp);
}

V3GraphVertex::V3GraphVertex(V3Graph* graphp)
    : m_fanout{0}
    , m_color{0}
    , m_rank{0} {
    m_userp = nullptr;
    verticesPushBack(graphp);
}

void V3GraphVertex::verticesPushBack(V3Graph* graphp) {
    m_vertices.pushBack(graphp->m_vertices, this);
}

void V3GraphVertex::unlinkEdges(V3Graph*) {
    for (V3GraphEdge* edgep = outBeginp(); edgep; /*BELOW*/) {
        V3GraphEdge* nextp = edgep->outNextp();
        edgep->unlinkDelete();
        edgep = nextp;
    }
    for (V3GraphEdge* edgep = inBeginp(); edgep; /*BELOW*/) {
        V3GraphEdge* nextp = edgep->inNextp();
        edgep->unlinkDelete();
        edgep = nextp;
    }
}

void V3GraphVertex::unlinkDelete(V3Graph* graphp) {
    // Delete edges
    unlinkEdges(graphp);
    // Unlink from vertex list
    m_vertices.unlink(graphp->m_vertices, this);
    // Delete
    delete this;  // this=nullptr;
}

void V3GraphVertex::rerouteEdges(V3Graph* graphp) {
    // Make new edges for each from/to pair
    for (V3GraphEdge* iedgep = inBeginp(); iedgep; iedgep = iedgep->inNextp()) {
        for (V3GraphEdge* oedgep = outBeginp(); oedgep; oedgep = oedgep->outNextp()) {
            new V3GraphEdge{graphp, iedgep->fromp(), oedgep->top(),
                            std::min(iedgep->weight(), oedgep->weight()),
                            iedgep->cutable() && oedgep->cutable()};
        }
    }
    // Remove old edges
    unlinkEdges(graphp);
}

bool V3GraphVertex::inSize1() const { return !inEmpty() && !inBeginp()->inNextp(); }
bool V3GraphVertex::outSize1() const { return !outEmpty() && !outBeginp()->outNextp(); }

V3GraphEdge* V3GraphVertex::findConnectingEdgep(GraphWay way, const V3GraphVertex* waywardp) {
    // O(edges) linear search. Searches search both nodes' edge lists in
    // parallel.  The lists probably aren't _both_ huge, so this is
    // unlikely to blow up even on fairly nasty graphs.
    const GraphWay inv = way.invert();
    V3GraphEdge* aedgep = this->beginp(way);
    V3GraphEdge* bedgep = waywardp->beginp(inv);
    while (aedgep && bedgep) {
        if (aedgep->furtherp(way) == waywardp) return aedgep;
        if (bedgep->furtherp(inv) == this) return bedgep;
        aedgep = aedgep->nextp(way);
        bedgep = bedgep->nextp(inv);
    }
    return nullptr;
}

// cppcheck-has-bug-suppress constParameter
void V3GraphVertex::v3errorEnd(std::ostringstream& str) const VL_RELEASE(V3Error::s().m_mutex) {
    std::ostringstream nsstr;
    nsstr << str.str();
    if (debug()) {
        nsstr << endl;
        nsstr << "-vertex: " << this << endl;
    }
    if (FileLine* const flp = fileline()) {
        flp->v3errorEnd(nsstr);
    } else {
        V3Error::v3errorEnd(nsstr);
    }
}
void V3GraphVertex::v3errorEndFatal(std::ostringstream& str) const
    VL_RELEASE(V3Error::s().m_mutex) {
    v3errorEnd(str);
    assert(0);  // LCOV_EXCL_LINE
    VL_UNREACHABLE;
}

std::ostream& operator<<(std::ostream& os, V3GraphVertex* vertexp) {
    os << "  VERTEX=" << vertexp->name();
    if (vertexp->rank()) os << " r" << vertexp->rank();
    if (vertexp->fanout() != 0.0) os << " f" << vertexp->fanout();
    if (vertexp->color()) os << " c" << vertexp->color();
    return os;
}

//######################################################################
//######################################################################
// Edges

void V3GraphEdge::init(V3Graph* /*graphp*/, V3GraphVertex* fromp, V3GraphVertex* top, int weight,
                       bool cutable) {
    UASSERT(fromp, "Null from pointer");
    UASSERT(top, "Null to pointer");
    m_fromp = fromp;
    m_top = top;
    m_weight = weight;
    m_cutable = cutable;
    m_userp = nullptr;
    // Link vertices to this edge
    outPushBack();
    inPushBack();
}

V3GraphEdge* V3GraphEdge::relinkFromp(V3GraphVertex* newFromp) {
    V3GraphEdge* oldNxt = outNextp();
    m_outs.unlink(m_fromp->m_outs, this);
    m_fromp = newFromp;
    outPushBack();
    return oldNxt;
}

V3GraphEdge* V3GraphEdge::relinkTop(V3GraphVertex* newTop) {
    V3GraphEdge* oldNxt = inNextp();
    m_ins.unlink(m_top->m_ins, this);
    m_top = newTop;
    inPushBack();
    return oldNxt;
}

void V3GraphEdge::unlinkDelete() {
    // Unlink from side
    m_outs.unlink(m_fromp->m_outs, this);
    // Unlink to side
    m_ins.unlink(m_top->m_ins, this);
    // Delete
    delete this;  // this=nullptr;
}

void V3GraphEdge::outPushBack() {
    // m_fromp->m_outsp.push_back(this);
    m_outs.pushBack(m_fromp->m_outs, this);
}

void V3GraphEdge::inPushBack() {
    // m_top->m_insp.push_back(this);
    m_ins.pushBack(m_top->m_ins, this);
}

//######################################################################
//######################################################################
// Graph top level
// Constructors

V3Graph::V3Graph() {
    // Anything here is probably needed in clear() also
    verticesUnlink();
}

V3Graph::~V3Graph() { clear(); }

void V3Graph::clear() {
    // Empty it of all points, as if making a new object
    // Delete the old edges
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; vertexp = vertexp->verticesNextp()) {
        for (V3GraphEdge* edgep = vertexp->outBeginp(); edgep; /*BELOW*/) {
            V3GraphEdge* nextp = edgep->outNextp();
            VL_DO_DANGLING(delete edgep, edgep);
            edgep = nextp;
        }
        vertexp->outUnlink();
    }
    // Delete the old vertices
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; /*BELOW*/) {
        V3GraphVertex* nextp = vertexp->verticesNextp();
        VL_DO_DANGLING(delete vertexp, vertexp);
        vertexp = nextp;
    }
    verticesUnlink();
}

void V3Graph::userClearVertices() {
    // Clear user() in all of tree
    // We may use the userCnt trick in V3Ast later... (but gblCnt would be
    // in V3Graph instead of static - which has the complication of finding
    // the graph pointer given a vertex.)  For now we don't call this often, and
    // the extra code on each read of user() would probably slow things
    // down more than help.
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; vertexp = vertexp->verticesNextp()) {
        vertexp->user(0);
        vertexp->userp(nullptr);  // Its a union, but might be different size than user()
    }
}

void V3Graph::userClearEdges() {
    // Clear user() in all of tree
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; vertexp = vertexp->verticesNextp()) {
        for (V3GraphEdge* edgep = vertexp->outBeginp(); edgep; edgep = edgep->outNextp()) {
            edgep->user(0);
            edgep->userp(nullptr);  // Its a union, but might be different size than user()
        }
    }
}

void V3Graph::clearColors() {
    // Reset colors
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; vertexp = vertexp->verticesNextp()) {
        vertexp->m_color = 0;
    }
}

//======================================================================
// Dumping

void V3Graph::loopsMessageCb(V3GraphVertex* vertexp) {
    vertexp->v3fatalSrc("Loops detected in graph: " << vertexp);
}

void V3Graph::loopsVertexCb(V3GraphVertex* vertexp) {
    // Needed here as V3GraphVertex<< isn't defined until later in header
    if (debug()) std::cerr << "-Info-Loop: " << cvtToHex(vertexp) << " " << vertexp << endl;
}

void V3Graph::dump(std::ostream& os) const {
    // This generates a file used by graphviz, https://www.graphviz.org
    os << " Graph:\n";
    // Print vertices
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; vertexp = vertexp->verticesNextp()) {
        os << "\tNode: " << vertexp->name();
        if (vertexp->color()) os << "  color=" << vertexp->color();
        os << '\n';
        // Print edges
        for (V3GraphEdge* edgep = vertexp->inBeginp(); edgep; edgep = edgep->inNextp()) {
            dumpEdge(os, vertexp, edgep);
        }
        for (V3GraphEdge* edgep = vertexp->outBeginp(); edgep; edgep = edgep->outNextp()) {
            dumpEdge(os, vertexp, edgep);
        }
    }
}

void V3Graph::dumpEdge(std::ostream& os, const V3GraphVertex* vertexp,
                       const V3GraphEdge* edgep) const {
    if (edgep->weight() && (edgep->fromp() == vertexp || edgep->top() == vertexp)) {
        os << "\t\t";
        if (edgep->fromp() == vertexp) os << "-> " << edgep->top()->name();
        if (edgep->top() == vertexp) os << "<- " << edgep->fromp()->name();
        if (edgep->cutable()) os << "  [CUTABLE]";
        os << '\n';
    }
}
void V3Graph::dumpEdges(std::ostream& os, const V3GraphVertex* vertexp) const {
    for (const V3GraphEdge* edgep = vertexp->inBeginp(); edgep; edgep = edgep->inNextp())
        dumpEdge(os, vertexp, edgep);
    for (const V3GraphEdge* edgep = vertexp->outBeginp(); edgep; edgep = edgep->outNextp())
        dumpEdge(os, vertexp, edgep);
}

void V3Graph::dumpDotFilePrefixed(const string& nameComment, bool colorAsSubgraph) const {
    dumpDotFile(v3Global.debugFilename(nameComment) + ".dot", colorAsSubgraph);
}

//! Variant of dumpDotFilePrefixed without --dump option check
void V3Graph::dumpDotFilePrefixedAlways(const string& nameComment, bool colorAsSubgraph) const {
    dumpDotFile(v3Global.debugFilename(nameComment) + ".dot", colorAsSubgraph);
}

void V3Graph::dumpDotFile(const string& filename, bool colorAsSubgraph) const {
    // This generates a file used by graphviz, https://www.graphviz.org
    // "hardcoded" parameters:
    const std::unique_ptr<std::ofstream> logp{V3File::new_ofstream(filename)};
    if (logp->fail()) v3fatal("Can't write " << filename);

    // Header
    *logp << "digraph v3graph {\n";
    *logp << "\tgraph\t[label=\"" << filename << "\",\n";
    *logp << "\t\t labelloc=t, labeljust=l,\n";
    *logp << "\t\t //size=\"7.5,10\",\n";
    *logp << "\t\t rankdir=" << dotRankDir() << "];\n";

    // List of all possible subgraphs
    // Collections of explicit ranks
    std::unordered_set<std::string> ranks;
    std::unordered_multimap<std::string, V3GraphVertex*> rankSets;
    std::multimap<std::string, V3GraphVertex*> subgraphs;
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; vertexp = vertexp->verticesNextp()) {
        const string vertexSubgraph
            = (colorAsSubgraph && vertexp->color()) ? cvtToStr(vertexp->color()) : "";
        subgraphs.emplace(vertexSubgraph, vertexp);
        const string& dotRank = vertexp->dotRank();
        if (!dotRank.empty()) {
            ranks.emplace(dotRank);
            rankSets.emplace(dotRank, vertexp);
        }
    }

    // We use a map here, as we don't want to corrupt anything (userp) in the graph,
    // and we don't care if this is slow.
    std::unordered_map<const V3GraphVertex*, int> numMap;

    // Print vertices
    int n = 0;
    string subgr;
    for (auto it = subgraphs.cbegin(); it != subgraphs.cend(); ++it) {
        const string vertexSubgraph = it->first;
        const V3GraphVertex* vertexp = it->second;
        numMap[vertexp] = n;
        if (subgr != vertexSubgraph) {
            if (subgr != "") *logp << "\t};\n";
            subgr = vertexSubgraph;
            if (subgr != "") {
                *logp << "\tsubgraph cluster_" << subgr << " {\n";
                *logp << "\tlabel=\"" << subgr << "\"\n";
            }
        }
        if (subgr != "") *logp << "\t";
        *logp << "\tn" << vertexp->dotName() << (n++) << "\t[fontsize=8 "
              << "label=\"" << (vertexp->name() != "" ? vertexp->name() : "\\N");
        if (vertexp->rank()) *logp << " r" << vertexp->rank();
        if (vertexp->fanout() != 0.0) *logp << " f" << vertexp->fanout();
        if (vertexp->color()) *logp << "\\n c" << vertexp->color();
        *logp << "\"";
        *logp << ", color=" << vertexp->dotColor();
        if (vertexp->dotStyle() != "") *logp << ", style=" << vertexp->dotStyle();
        if (vertexp->dotShape() != "") *logp << ", shape=" << vertexp->dotShape();
        *logp << "];\n";
    }
    if (subgr != "") *logp << "\t};\n";

    // Print edges
    for (V3GraphVertex* vertexp = verticesBeginp(); vertexp; vertexp = vertexp->verticesNextp()) {
        for (V3GraphEdge* edgep = vertexp->outBeginp(); edgep; edgep = edgep->outNextp()) {
            if (edgep->weight()) {
                const int fromVnum = numMap[edgep->fromp()];
                const int toVnum = numMap[edgep->top()];
                *logp << "\tn" << edgep->fromp()->dotName() << fromVnum << " -> n"
                      << edgep->top()->dotName() << toVnum
                      << " ["
                      // <<"fontsize=8 label=\""<<(edgep->name()!="" ? edgep->name() : "\\E")<<"\""
                      << "fontsize=8 label=\""
                      << (edgep->dotLabel() != "" ? edgep->dotLabel() : "") << "\""
                      << " weight=" << edgep->weight() << " color=" << edgep->dotColor();
                if (edgep->dotStyle() != "") *logp << " style=" << edgep->dotStyle();
                // if (edgep->cutable()) *logp << ",constraint=false";  // to rank without
                // following edges
                *logp << "];\n";
            }
        }
    }

    // Print ranks
    for (const auto& dotRank : ranks) {
        *logp << "\t{ rank=";
        if (dotRank != "sink" && dotRank != "source" && dotRank != "min" && dotRank != "max") {
            *logp << "same";
        } else {
            *logp << dotRank;
        }
        *logp << "; ";
        auto bounds = rankSets.equal_range(dotRank);
        for (auto it{bounds.first}; it != bounds.second; ++it) {
            if (it != bounds.first) *logp << ", ";
            *logp << 'n' << numMap[it->second] << "";
        }
        *logp << " }\n";
    }

    // Vertex::m_user end, now unused

    // Trailer
    *logp << "}\n";
    logp->close();

    cout << "dot -Tpdf -o ~/a.pdf " << filename << "\n";
}
