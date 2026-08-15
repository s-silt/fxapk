"""apkscan.analyzers — 静态分析器（零环境，永远可用）。

registry.discover_analyzers() 会用 pkgutil 自动发现本包内所有 BaseAnalyzer 具体子类，
新增分析器模块无需改任何中心文件。
"""
