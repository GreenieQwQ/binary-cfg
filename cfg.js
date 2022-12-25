/*
/* Cfg viewer V0.2
*/

// global var
var nodes = null;
var svg = null;
var brush = null;
var brushg = null;
var selectedNode = null;
var timeout = null;

// function var
var clearFocus = null;
var allFocus = null;
var textUpdate = null;


d3.json('data/nodes.json', d => {
    nodes = d;

    /* Data Post-Process */
    nodes.forEach(node => {
        node.content.head.name = node.content.head.name ? node.content.head.name : "jmp";
        node.content.asm = node.content.asm ? node.content.asm : [];
        node.doi_type = DOI_TYPE.LITTLE_CARE;
        node.owner = null;
        node.container = [];
        node.is_fold = false;
        node.is_manual_focus = false;
        node.text = getNodeText(nodes, node);
        node.size = getNodeSize(nodes, node);
        node.shortestPathParent = null;
        node.note = "";
    });

    cfgviewer(d);
});


/* Main */
function cfgviewer(nodes) {
    /* Btn or Textarea Update Function */
    // 清零按钮触发函数
    clearFocus = () => {
        nodes.forEach(node => {
            node.doi_type = DOI_TYPE.LITTLE_CARE;
            node.is_manual_focus = false;
            if (node.container.length != 0)
                untieNodes(nodes, node.id);
        });
        selectedNode = null;
        update(nodes);
    };

    // 全关注按钮触发函数
    allFocus = () => {
        nodes.forEach(node => node.is_manual_focus = true);
        update(nodes);
    };

    // 设置文本框触发函数
    textUpdate = () => {
        let text = d3.select(".textboard").select("textarea").node().value;
        nodes[selectedNode].note = text;
    }

    /* SVG */
    svg = d3.select("body").append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("style", "max-width: 100%; height: auto; height: intrinsic;")
        .attr("font-family", "sans-serif")
        .attr("font-size", 10)
        .attr("class", "board");
    
    /* Marker */
    // Arrow
    let marker = svg.append("defs").append("marker")
        .attr("id", "arrow")
        .attr("markerUnits", "strokeWidth")
        .attr("markerWidth", 5)
        .attr("markerHeight", 4)
        .attr("refX", 5)
        .attr("refY", 2)
        .attr("orient", "auto");

    marker.append("path")
        .attr("d", "M 0 0 L 5 2 L 0 4 z")
        .attr("fill", "#707070");

    /* Brush */
    var xScale = d3.scale.linear().domain([0, width]).range([0, width]);
    var yScale = d3.scale.linear().domain([0, height]).range([0, height]);
    brush = d3.svg.brush()
        .x(xScale)
        .y(yScale)
        .extent([[0, 0], [0, 0]])
        .on("brushstart", brushStart)
        .on("brush", brushMove)
        .on("brushend", brushEnd);

    brushg = svg.append("g")
        .attr("class", "brush")
        .call(brush);

    /* Update at first */
    update(nodes);
}

/* Update */
function update(nodes) {
    /* Node Update */
    nodes.forEach(n => {
        n.text = getNodeText(nodes, n);
        n.size = getNodeSize(nodes, n);
    });

    let [dnodes, links] = getNodesAndLinks(nodes);

    /* Dagre Layout */
    const g = new dagre.graphlib.Graph()
        .setGraph({ rankdir: "TB", marginx: 50, marginy: 50, ranksep: 55 })
        .setDefaultEdgeLabel(() => ({}));

    dnodes.forEach(node => {
        g.setNode(node.id, { width: node.size[0], height: node.size[1]});
    });

    links.forEach(link => {
        g.setEdge(link.source, link.target);
    });

    dagre.layout(g);

    dagreNodes = g.nodes().map(id => {
        const node = nodes[id];
        const dnode = g.node(id);
        node.x = dnode.x;
        node.y = dnode.y;
        return node;
    });
    
    /* View Box(Auto Layout for svg) */
    // TODO: Wait Implementation

    // let viewX = Infinity;  // 所有节点最左侧的X坐标
    // let viewY = Infinity;  // 所有节点最顶部的Y坐标
    // let viewW = 0;  // 给定最左侧X坐标时，所有节点最右侧坐标到X的距离
    // let viewH = 0;  // 同理

    // dagreNodes.forEach(n => {
    //     viewX = Math.min(viewX, n.x - n.size[0] / 2);
    //     viewY = Math.min(viewY, n.y - n.size[1] / 2);
    // })
    // dagreNodes.forEach(n => {
    //     viewW = Math.max(viewW, n.x + n.size[0] / 2);
    //     viewH = Math.max(viewH, n.y + n.size[1] / 2);
    // })
    // console.log(viewX, viewY, viewW, viewH);
    // svg.attr("width", viewW);
    // svg.attr("height", viewH);
    // svg.attr("viewBox", [viewX, viewY, viewW, viewH]);
    // svg.attr("viewBox", [dagreNodes[0].x - width / 2, dagreNodes[0].y - 50, width, height]);
    
    /*
    /* ===== Node Processing =====
    */
    let gnode = svg.selectAll("g.node")
        .data(dagreNodes, d => d.id);
    
    // Entering
    let nodeEnter = gnode.enter().append("g")
        .attr("class", "node")
        .attr("id", n => "node_" + n.id)
        .on("click", click)
        .on("dblclick", dblclick)
        .on("contextmenu", contextmenu);

    nodeEnter.append("g").append("rect")
        .attr("rx", roundScale)
        .attr("ry", roundScale)
        .attr("width", 0)
        .attr("height", 0)
        .attr("x", n => n.x)
        .attr("y", n => n.y);

    nodeEnter.select("g").append("line")
        .attr("x1", n => n.x)
        .attr("y1", n => n.y)
        .attr("x2", n => n.x)
        .attr("y2", n => n.y)

    // Text
    nodeEnter.append("g")
        .attr("class", "head");
    
    nodeEnter.append("g")
        .attr("class", "content");

    // 不能对nodeEnter进行此操作，否则合并节点后由于没有新增节点，
    // 已有节点内部head和content的text数量不会变化
    let headBinder = gnode.select("g.head")
        .selectAll("text")
        .data(d => d.text[0]);

    headBinder.enter()
        .append("text")
        .attr("text-anchor", "middle")
        .style("fill-opacity", 0);

    let contentBinder = gnode.select("g.content")
        .selectAll("text")
        .data(d => d.text[1]);

    contentBinder.enter()
        .append("text")
        .style("fill-opacity", 0);

    // Updating: from origin pos to new pos
    let nodeUpdate = gnode.transition()
        .duration(duration);
    
    nodeUpdate.select("g").select("rect")
        .attr("x", n => n.x - n.size[0] / 2)
        .attr("y", n => n.y - n.size[1] / 2)
        .attr("width", n => n.size[0])
        .attr("height", n => n.size[1])
        .style("fill", d => {
            if (!d.is_fold && d.container.length == 0) {
                if(d.doi_type == DOI_TYPE.MOST_CARE || d.is_manual_focus)
                    return NODE_COLOR.MOST_FOCUS;
                else if(d.doi_type == DOI_TYPE.MEDIEAN_CARE)
                    return NODE_COLOR.MEDIEAN_FOCUS;
                else
                    return NODE_COLOR.NORMAL;
            } else if (d.is_fold && d.container.length == 0) {
                return NODE_COLOR.FOLD;
            } else if (!d.is_fold && d.container.length != 0) {
                return NODE_COLOR.MERGE;
            } else {
                return NODE_COLOR.FOLD_AND_MERGE;
            }
        });

    nodeUpdate.select("g").select("line")
        .attr("x1", n => n.x - n.size[0] / 2)
        .attr("y1", n => {
            let startY = n.y - n.size[1] / 2;
            let head_lines = n.text[0].length;
            return startY + TEXT_PADDING.HEAD_TOP + head_lines * TEXT_PADDING.HEAD_HEIGHT + TEXT_PADDING.HEAD_BOTTOM;
        })
        .attr("x2", n => {
            return n.x + n.size[0] / 2;
        })
        .attr("y2", n => {
            let startY = n.y - n.size[1] / 2;
            let head_lines = n.text[0].length;
            return startY + TEXT_PADDING.HEAD_TOP + head_lines * TEXT_PADDING.HEAD_HEIGHT + TEXT_PADDING.HEAD_BOTTOM
        })
        .style("visibility", n => n.text[1].length == 0 ? "hidden" : "visible");

    // Update Text
    nodeUpdate.select("g.head")
        .selectAll("text")
        .attr("x", d => {
            let n = nodes[d.id];
            return n.x;
        })
        .attr("y", (d, i) => {
            let n = nodes[d.id];
            let startY = n.y - n.size[1] / 2;
            return startY + TEXT_PADDING.HEAD_TOP + (i + 1) * TEXT_PADDING.HEAD_HEIGHT;
        })
        .text(d => {
            return d.content;
        })
        .style("fill-opacity", 1);
    
    nodeUpdate.select("g.content")
        .selectAll("text")
        .attr("x", d => {
            let n = nodes[d.id];
            let startX = n.x - n.size[0] / 2;
            return startX + TEXT_PADDING.CONTENT_LEFT;
        })
        .attr("y", (d, i) => {
            let n = nodes[d.id];
            let startY = n.y - n.size[1] / 2;
            startY += TEXT_PADDING.HEAD_TOP + TEXT_PADDING.HEAD_HEIGHT + TEXT_PADDING.HEAD_BOTTOM;
            startY += TEXT_PADDING.CONTENT_TOP + (i + 1) * TEXT_PADDING.CONTENT_HEIGHT;
            return startY;
        })
        .text(d => d.content)
        .style("fill-opacity", 1);

    // Exiting
    let nodeExit = gnode.exit().transition()
        .duration(duration)
        .remove();

    nodeExit.selectAll("rect")
        .attr("width", 0)
        .attr("height", 0);

    nodeExit.selectAll("line")
        .attr("x1", n => n.x)
        .attr("y1", n => n.y)
        .attr("x2", n => n.x)
        .attr("y2", n => n.y);

    nodeExit.selectAll("text")
        .style("fill-opacity", 0);

    headBinder.exit()
        .remove();

    contentBinder.exit()
        .remove();

    /*
    /* ===== Link Processing =====
    */

    // Entering
    const edges = g.edges()
        .map(d => {
            const dedge = g.edge(d);
            const edge = links.find(e => e.source == d.v && e.target == d.w);
            dedge.source = edge.source;
            dedge.target = edge.target;
            return dedge;
        })

    let link = svg
        .selectAll("path.link")
        .data(edges, d => d.source + "," +  d.target);

    // Add new links at source's old pos
    link.enter().insert("path", "g")
        .attr("class", "link");

    // Set links to their new pos.
    let line = d3.svg.line()
                .x(d => d.x)
                .y(d => d.y)
                .interpolate("basis");

    link.transition()
        .duration(duration)
        // .delay(duration * 0.5)
        .attr("d", d => line(d.points))
        .attr("style", "marker-end: url(#arrow);");

    // Remove any links exiting.
    link.exit().transition()
        // .duration(duration)
        // .attr("d", d => {
        //     let o = {x: d.source.x ? d.source.x : 0, y: d.source.y ? d.source.y + d.source.size[1] / 2 : 0};
        //     return diagonal({source: o, target: o});
        // })
        .remove();

    /*
    /* ===== TextArea =====
    */
    let node = nodes[selectedNode == null ? 0 : selectedNode];
    let clientRect = d3.select("#node_" + node.id)
        .select("rect")
        .node()
        .getBoundingClientRect();
    let textarea_line = Math.floor(node.size[1] / TEXTAREA.LINE_HEIGHT);
    let textarea_height = TEXTAREA.HEIGHT_PADDING + TEXTAREA.LINE_HEIGHT * textarea_line;
    
    let bias = (clientRect.height - textarea_height) / 2;
    console.log(clientRect)

    let textboard = d3.select(".textboard")
        .style("top", clientRect.top + bias + "px")
        .style("left", clientRect.right + "px")
        .style("visibility", selectedNode == null ? "hidden" : "visible");

    textboard.select("textarea")
        .attr("cols", 1)
        .attr("rows", textarea_line)
        .style("visibility", "hidden");

    let textboardUpdate = textboard.transition()
        .duration(duration)
        .style("visibility", selectedNode == null ? "hidden" : "visible");
    
    let textareaUpdate = textboardUpdate.select("textarea")
        .attr("cols", node.size[0] / 8)
        .attr("rows", textarea_line)
        .style("visibility", selectedNode == null ? "hidden" : "visible");

    textareaUpdate.node().value = node.note;

    /*
    /* ===== Post processing =====
    */

    // Record the old positions.
    nodes.forEach(d => {
        d.x0 = d.x;
        d.y0 = d.y;
    });
}

/* Event Handler */
function click(n) {
    if (d3.event.ctrlKey) {
        if (selectedNode == n.id)
            selectedNode = null;
        else
            selectedNode = n.id;
    } else {
        if (selectedNode != n.id)
            selectedNode = null;
            setDOI(nodes, n);
    }
    update(nodes);
}

function contextmenu(n) {
    n.is_manual_focus = !n.is_manual_focus;
    d3.event.preventDefault();
    console.log(n);
    update(nodes);
}

function dblclick(n) {
    // n.is_fold = !n.is_fold
    // update(nodes);
}

function brushStart() {
}

function brushMove() {
}

function brushEnd() {
    let extent = brush.extent();
    let selectedNodes = [];
    let [dnodes, links] = getNodesAndLinks(nodes);
    dnodes.forEach(n => {
        let x1 = n.x - n.size[0] / 2;
        let y1 = n.y - n.size[1] / 2;
        let x2 = x1 + n.size[0];
        let y2 = y1 + n.size[1];
        if (isNodeInBox(x1, y1, extent) && isNodeInBox(x2, y2, extent))
            selectedNodes.push(n.id);
    })

    // close brush area
    brushg.selectAll("rect.extent")
        .attr("weight", 0)
        .attr("height", 0);

    function isNodeInBox(x, y, box) {
        if (box[0][0] <= x && x <= box[1][0] &&
            box[0][1] <= y && y <= box[1][1])
            return true;
        else
            return false;
    }

    // 框多个节点是合并，框一个节点是Zoom in
    if (selectedNodes.length == 1) {
        untieNodes(nodes, selectedNodes[0]);
    } else {
        mergeNodes(nodes, selectedNodes);
    }
    update(nodes);
}