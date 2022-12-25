import angr
from bingraphvis.angr import *
from bingraphvis import DotOutput

import argparse

import os
import json
from http.server import HTTPServer, CGIHTTPRequestHandler

def process(vis, obj=None, filter=None):
    # 自定义process，不使用bingraphvis提供的process
    vis.preprocess(obj)
    graph = vis.pipeline.process(filter=filter)
    return graph


def extract_node_info(node):
    info = {}
    info['id'] = node.id
    info['content'] = {}
    if node.content.get('head', None) is not None:
        info['content']['head'] = {
            'addr': node.content['head']['data'][0]['addr']['content'],
            'func_addr': node.content['head']['data'][0]['func_addr']['content'],
            'name': node.content['head']['data'][0]['name']['content'],
            'attributes': node.content['head']['data'][0]['attributes']['content']
        }
    if node.content.get('asm', None) is not None:
        info['content']['asm'] = [{
            'addr': item['addr']['content'],
            'mnemonic': item['mnemonic']['content'],
            'operands': item['operands']['content']
            } for item in node.content['asm']['data']
        ]
    if node.obj.byte_string is not None:
        info['content']['byte_string'] = str(node.obj.byte_string)
    info['content']['sign'] = {
        'has_return': node.obj.has_return,
        'is_simprocedure': node.obj.is_simprocedure,
        'is_syscall': node.obj.is_syscall,
        'no_ret': node.obj.no_ret
    }
    info['children'] = [node.id for node in node.children]

    return info


def get_start_id(nodes):
    # 统计出度和入度
    for node in nodes:
        for child in node.children:
            child.in_degree += 1
            node.out_degree += 1
    
    # 寻找入度为0的节点作为起始节点
    for node in nodes:
        if node.in_degree == 0 and node.out_degree != 0:
            return node
    
    # 没有入度为0的节点时，输出第一个出度不为0的节点
    for node in nodes:
        if node.out_degree != 0:
            return node


def dfs_gen_nodes(node, has_seen, dfs_nodes):
    has_seen.add(node)
    dfs_nodes.append(node)
    
    for child in node.children:
        if child in has_seen:
            continue
        dfs_gen_nodes(child, has_seen, dfs_nodes)
    
    return dfs_nodes


# def re_index(nodes, edges):
#     # 对节点、边重新设定id
#     ri_edges = []
#     adj_list = [[] for _ in range(len(nodes))]
#     for id, n in enumerate(nodes):
#         n.id = id
#     for e in edges:
#         src_id = e.src.id
#         dst_id = e.dst.id
#         ri_edges.append((src_id, dst_id))
#         adj_list[src_id].append(dst_id)
#     return nodes, ri_edges, adj_list


# def dfs_gen_root(start_id, nodes, adj_list, has_seen):
#     root_n = nodes[start_id]
#     root = extract_node_info(root_n)
#     has_seen.add(start_id)

#     for id in adj_list[start_id]:
#         if id in has_seen:
#             root['edge'].append(id)
#         else:
#             root['children'].append(dfs_gen_root(id, nodes, adj_list, has_seen))

#     return root


if __name__ == '__main__':
    # Parse Options
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", metavar="file", type=str, help="the bindary file used to explore")
    args = parser.parse_args()
    binary = args.file
    
    # Call Angr
    project = angr.Project(binary, load_options={'auto_load_libs': False})
    main_start = project.loader.main_object.get_symbol('main')
    start_state = project.factory.blank_state(addr=main_start.rebased_addr)
    cfg = project.analyses.CFGEmulated(fail_fast=True, starts=[main_start.rebased_addr], initial_state=start_state)
    # cfg = project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True,
    #                                symbols=True, function_prologues=True, force_complete_scan=True,
    #                                collect_data_references=False, resolve_indirect_jumps=True)

    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=True, remove_path_terminator=True)
    vis.add_transformer(AngrRemoveImports(cfg.project))
    vis.set_output(DotOutput("test.png", format='svg'))

    # vis.process(cfg.graph)
    # cgraph = vis.pipeline.node_annotators[0].graph
    cgraph = process(vis, cfg.graph)
    nodes = list(cgraph.nodes)
    edges = cgraph.edges

    # Generate Node List
    for n in nodes:
        n.children = []
        n.in_degree = 0
        n.out_degree = 0
    for e in edges:
        e.src.children.append(e.dst)
    dfs_nodes = []
    has_seen = set()
    dfs_gen_nodes(get_start_id(nodes), has_seen, dfs_nodes)

    # Avoid isolated nodes
    for n in nodes:
        if n not in dfs_nodes:
            dfs_nodes.append(n)

    # Indexing
    for i, node in enumerate(dfs_nodes):
        node.id = i
    
    nodes_js = [extract_node_info(node) for node in dfs_nodes]

    with open("data/nodes.json", "w") as f:
        json.dump(nodes_js, f)

    # Open a HTTP Server
    os.chdir("./")
    HTTPServer(('127.0.0.1', 8181), CGIHTTPRequestHandler).serve_forever()
