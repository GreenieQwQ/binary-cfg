function getNodesAndLinks(nodes) {
    // 利用DFS生成需要绘制的节点和边，忽略折叠的、合并的节点及边
    let visited = new Set();
    let links = new Set();
    let dnodes = [];
    function getLinksFromNode(node) {
        if (visited.has(node.id)) return;
        visited.add(node.id);
        // Add Node
        if (node.owner == null)
            dnodes.push(node);
        // Add Path
        let src_id = getOwner(node.id);
        if (!node.is_fold) {
            node.children.forEach(child => {
                let tgt_id = getOwner(child);
                if (src_id != tgt_id) {
                    links.add({
                        source: src_id,
                        target: tgt_id
                    });
                }
                getLinksFromNode(nodes[child]);
            })
        }
    }
    getLinksFromNode(nodes[0]);
    return [dnodes, Array.from(links)];

    function getOwner(id) {
        let owner = id;
        while (nodes[owner].owner != null) owner = nodes[owner].owner;
        return owner;
    }
}

function getDescendants(nodes, node) {
    // 获取从node出发可以抵达的所有节点
    let visited = new Set();
    let descendants = [];
    function addChildren(node) {
        if (visited.has(node.id)) return;
        visited.add(node.id);
        node.children.forEach(child => {
            descendants.push(child);
            addChildren(nodes[child]);
        })
    }
    addChildren(node);
    return descendants.map(Number);
}

// 功能：从节点中基于节点doi/合并情况获取节点文本（head + content）
// 若节点是合并的 则只显示head不显示内容 否则基于doi展示内容
function getNodeText(nodes, node) {
    // 计算head
    let head = [];
    function getContainerHead(n) {
        head.push({
            id: node.id,
            content: n.content.head.addr + " " + n.content.head.func_addr + " " + n.content.head.name
        });
        n.container.forEach(id => {
            getContainerHead(nodes[id]);
        })
    }
    getContainerHead(node);
    // 计算content
    let getAsmString = a => a.addr + " " + a.mnemonic + " " + a.operands;
    let content = [];
    // d.container.length == 0代表不为merge节点
    if (node.container.length == 0) {
        // 基于doi展开内容
        if(node.is_manual_focus ||
            node.doi_type == DOI_TYPE.MOST_CARE || 
            (node.doi_type == DOI_TYPE.MEDIEAN_CARE && node.content.asm.length <= 3)) {
            // 最关心节点——展示全部asm
            node.content.asm.forEach(asm => {
                content.push({
                    id: node.id,
                    content: getAsmString(asm)
                });
            });
        } else if(node.doi_type == DOI_TYPE.MEDIEAN_CARE) {
            // 普通关心节点——仅展示首尾asm
            // console.log("node:", node)
            // console.log("asm0:", node.content.asm[0])
            content.push({
                id: node.id,
                content: getAsmString(node.content.asm[0])
            });
            content.push({
                id: node.id,
                content: "..."
            });
            content.push({
                id: node.id,
                content: getAsmString(node.content.asm[node.content.asm.length-1])
            });
        } else {
            head[0].content = head[0].content + " <F>";
            // 不关心节点——仅显示head
            // if(node.content.asm.length > 0)
            //     content.push({id: node.id, content: "..."});
        }
        
    }

    return [head, content];
}

function getNodeSize(nodes, node) {
    node.text = getNodeText(nodes, node);
    const [head, content] = node.text;
    const max = Math.max;
    const maxHeadLength = head.reduce((v, h) => max(v, max(v, h.content.length)), 0);
    const maxContentLength = content.reduce((v, c) => max(v, max(v, c.content.length)), 0);
    const width = max(maxHeadLength, maxContentLength) * TEXT_PADDING.TEXT_WIDTH;
    let height = TEXT_PADDING.HEAD_TOP + head.length * TEXT_PADDING.HEAD_HEIGHT + TEXT_PADDING.HEAD_BOTTOM;
    if(content.length)
        height += TEXT_PADDING.CONTENT_TOP + content.length * TEXT_PADDING.CONTENT_HEIGHT + TEXT_PADDING.CONTENT_BOTTOM;
    return [width, height]
}


/* Interaction */
/* Nodes and Links Function*/
function mergeNodes(nodes, merge_ids) {
    // 检查merge_nodes必须是具有线性关系的节点
    merge_ids = merge_ids.map(Number);
    if (merge_ids.length < 2) return;
    for (let i = 0; i < merge_ids.length - 1; i += 1) {
        if (!getDescendants(nodes, nodes[merge_ids[i]]).includes(merge_ids[i + 1])) {
            console.log("Invalid Merge:", merge_ids);
            return;
        }
    }
    // 合并节点（假设节点已按先后顺序排列好）
    let topNode = nodes[merge_ids[0]];
    for (let i = 1; i < merge_ids.length; i += 1) {
        let node = nodes[merge_ids[i]];

        topNode.container.push(merge_ids[i]);
        node.owner = merge_ids[0];
    }
    return nodes;
}

function untieNodes(nodes, id) {
    // 将主节点展开
    let node = nodes[id];
    if (node.container.length == 0) return;
    node.container.forEach(sub_id => {
        let sub_node = nodes[sub_id]
        sub_node.owner = null;
    })
    node.container = [];
}

/* DOI */
// 基于Bfs为节点设置最短路径 直到遇见node为止
// node为dummy时则对全图设置
function getMedianFocus(nodes, node) {
    let result = new Set();    // 存储median doi node的下标
    let havePushed = new Set();
    let queue = [];
    queue.push(0);
    havePushed.add(0);
    while(queue.length > 0) {
        const head = nodes[queue.pop()];
        // console.log("head:", head);
        // if(head.id == node.id)
        //     break;
        head.children.forEach(childID => {
            if(childID == node.id) {
                result.add(head.id);    
            }

            if(!havePushed.has(childID)) {
                queue.push(childID);
                havePushed.add(childID);
                nodes[childID].shortestPathParent = head.id;   
            }
        });
    }

    // 获取最短路径
    function getPath(nID) {
        const n = nodes[nID];
        // console.log("n:", n);
        result.add(nID);
        if(n.shortestPathParent == null)
            return;
        else
            getPath(n.shortestPathParent);
    }
    getPath(node.id);
    // 加入儿子
    // console.log("Before:", result);
    node.children.forEach(childID => {result.add(childID)});
    // console.log("children:", node.children);
    // console.log("after:", result);
    // 返回节点
    return nodes.filter(n => result.has(n.id));
}

function setDOI(nodes, node) {
    nodes.forEach(n => n.doi_type = DOI_TYPE.LITTLE_CARE);
    const MEDIEAN_CARE_NODES = getMedianFocus(nodes, node);
    // console.log("Median:", MEDIEAN_CARE_NODES);
    MEDIEAN_CARE_NODES.forEach(n => n.doi_type = DOI_TYPE.MEDIEAN_CARE);
    node.doi_type = DOI_TYPE.MOST_CARE;
}