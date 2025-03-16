from graphviz import Digraph

# Create a new directed graph
flowchart = Digraph("WiFiSecurityFlow", format="png")
flowchart.attr(bgcolor="#f4f4f4", dpi="150")  # Light background and high quality

# Styling attributes
node_style = {
    "shape": "rect",
    "style": "filled",
    "fontname": "Arial",
    "fontsize": "12"
}

# Define Nodes (Process Steps)
flowchart.node("A", "User Starts Wi-Fi Scan", **node_style, fillcolor="#4CAF50", fontcolor="white")
flowchart.node("B", "Wi-Fi Scanner Captures Data", **node_style, fillcolor="#2196F3", fontcolor="white")
flowchart.node("C", "Threat Detector Analyzes Network", **node_style, fillcolor="#FF9800", fontcolor="white")
flowchart.node("D", "Log Data in Database (MongoDB)", **node_style, fillcolor="#673AB7", fontcolor="white")
flowchart.node("E", "Threat Detected?", shape="diamond", style="filled", fillcolor="#FFC107", fontname="Arial Bold", fontsize="12")
flowchart.node("F", "Notify User with Threat Details", **node_style, fillcolor="#F44336", fontcolor="white")
flowchart.node("G", "Show Safe Message", **node_style, fillcolor="#8BC34A", fontcolor="white")
flowchart.node("H", "User Takes Action or Ignores", **node_style, fillcolor="#009688", fontcolor="white")

# Define Edges (Connections)
flowchart.edge("A", "B", label="Start Scan", fontname="Arial")
flowchart.edge("B", "C", label="Send Data", fontname="Arial")
flowchart.edge("C", "E", label="Analyze Threats", fontname="Arial")
flowchart.edge("E", "F", label="Yes", fontname="Arial", color="red", penwidth="2.5")
flowchart.edge("E", "G", label="No", fontname="Arial", color="green", penwidth="2.5")
flowchart.edge("F", "D", label="Log Threat Details", fontname="Arial")
flowchart.edge("G", "H", label="User Sees Status", fontname="Arial")
flowchart.edge("F", "H", label="User Decides Response", fontname="Arial")

# Render the graph to file
flowchart.render("wifi_security_execution_flow", view=True)
