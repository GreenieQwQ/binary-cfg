### 前后端交换数据格式

```json
{
	'id': integer,
	'children': [
    	['id', ...],	// out node1
    	['id', ...],	// out node2
	],
	'content': {
		'head': {
            'addr': integer,
            'func_addr': integer,
            'name': str,
            'attributes': str	// is null most of time
        },
        'asm': [{
                'addr': integer,
                'mnemonic': str,
                'operands': str
            }, {
                ...
        }],
        'sign': {
            'has_return': bool,
            'is_simprocedure': bool,
            'is_syscall': bool,
            'no_ret': bool
        },
        'byte_string': str
	}
	'edge': [ids]
}
```




### CFG-Explorer的工作方式

核心文件：cli.py; endpoint.py

工作流程：

- CFGExplorerCLI.\_create\_cfg(): 从二进制文件路径生成CFG数据结构
  - project = angr.Project(binary_path)
  - cfg = project.analyses.CFGFast(settings)
- CFGVisEndpoint: 将CFG数据结构转为SVG
  - Dependency: bingraphviz(a tool to convert cfg to svg, written by another author)
  - vis = AngrVisFactory().default_cfg_pipeline(): 调用了bingraphvis的API
  - vis.set_output(DotOutput(output file path))
  - vis.process(cfg.graph, filter): 这一步写入了文件
  - return Response(f.read(), mimetype='image/svg+xml'): 这一步返回SVG
- AngrVisFactory: https://github.com/axt/bingraphvis
  - vis = Vis()
  - vis.add_content(AngrAsm(cfg.project))

- Vis(base.py in bingraphvis)
  - 包装了VisPipeLine
  - DotOutput.generate(graph)
- DotOutput(output.py in bingraphvis)
  - ret = Fixed Start
  - ret += self.generate_cluster(graph, cluster) for cluster in graph.get_clusters()
  - ret += self.render_edge(e) for e in graph.edges
  - ret += Fixed End
  - dotfile = XDot(ret)
  - dotfile.write(file path, format)
- XDot: inherit from pydot.Dot
- pydot
  - an interface to Graphviz
  - can parse and dump into DOT language used by GraphViz
  - DOT Language: https://www.graphviz.org/doc/info/lang.html



Other:

- CFG数据结构：
  - at its core, is a NetworkX di-graph. This means that all of the normal NetworkX APIs are available
  - https://docs.angr.io/built-in-analyses/cfg#cfgfast-details
- NetworkX
  - Drawing
    - provides basic functionality for visualizing graphs: 过于简单，所以bingraphvis基于NetworkX的graph数据结构自己写了一套SVG生成框架。
    - https://networkx.org/documentation/stable/reference/drawing.html



### Bingraphvis抽取CFG信息的方式

在Pipeline的preprocess中，接收graph，使用AngrCFGSource对节点、边进行预处理，用自己的Node和Edge类包装起来。

然后使用各种Annotator进行信息的提取、填充，包括AngrCFGHead、AngrColorSimprocedures、AngrAsm、AngrX86CommentsAsm、AngrCommentsDataRef、AngrColorEdgesAsmX86。

AngrAsm最为关键，它负责填充Node的详细信息，关键语句是content.py 259行的insns = self.project.factory.block(addr=addr, size=max_size, num_inst=size).capstone.insns。获取了每个节点的命令，将其填入了node.content。

在Pipeline的process中，使用外部给定的filter过滤需要的节点（在自己构建的Graph数据类型上操作），这时nodes和edges都只剩下了符合要求的节点。

这个关键的graph没有直接保存在Pipeline或Vis类中，而是在交由各种Annotator处理时，塞到了Pipeline.annotator内部，而且每个Annotator中都有相同的这个graph。



### Angr提供的节点信息

**Nodes: list**

obj.size: node ID

content.head:

- the node head info, only one item in dict

- dict format: {

  ​	'addr': {'content': ...},

  ​	'func_addr': {'content': ...},

  ​	'name': {'content': ...},

  ​	'attributes': {'content'}

  }

content.asm: 

- a list of content for this node; multiple items in dict

- dict format: {

  ​	'addr': {'content': ..., 'align': LEFT},

  ​	'mnemonic': {'content': ..., 'align': LEFT},

  ​	'operands': {'content': ..., 'align'}

​		}

obj.byte_string

obj.has_return: bool

obj.is_simprocedure: bool

obj.is_syscall: bool

obj.no_ret: bool

---

obj.predecessors: 连接的上一个节点（不保证在核心集中）

obj.successors: 连接的下一个节点（不保证在核心集中）

obj.addr: ?

function_address: ?

obj.block: ?

seq: ?

instruction_addrs: a list



**Edges: list**

src: Node

dst: Node

---

meta: ...



### 我们的功能需求

- 图节点大小放缩
- 节点合并和展开
- 节点注释
- 定位节点对应代码位置



### 可能的技术路线

- 全部交给后端python处理
  - 优点：
    - 不需要自己构造从图数据结构生成可视化图的JS代码
    - 可以大规模复用已有工具，节约时间
  - 缺点：
    - 我们对节点合并和展开功能可能会需要重写已有工具的代码（bingraphviz）
    - 基于别人的代码，数据结构的调整不够方便
- 后端提供图数据结构（json、xml等传输方式）；在前端绘制SVG和更新数据结构
  - 优点：
    - 在前端做节点合并展开、放大缩小等功能会很方便，能直接修改数据结构并更新
    - 后端非常简单，直接调用angr并传输数据结构就可以了
  - 缺点：
    - 需要写一套从图数据结构生成可视化图的JS代码
  - 其他：
    - 也许也有JS的从图数据结构生成SVG的框架，对它修改一下用上说不定也行。