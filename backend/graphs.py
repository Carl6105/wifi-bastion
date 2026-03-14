import matplotlib.pyplot as plt

# Data: Resource usage over a 60-second scan period
time_seconds = [0, 10, 20, 30, 40, 50, 60]
cpu_usage = [2, 12, 15, 14, 16, 15, 14] # % CPU usage
ram_usage = [45, 52, 58, 60, 62, 62, 62] # MB of RAM used

fig, ax1 = plt.subplots(figsize=(10, 6))

# CPU Line (Left Axis)
color = 'tab:blue'
ax1.set_xlabel('Scan Duration (Seconds)')
ax1.set_ylabel('CPU Usage (%)', color=color)
ax1.plot(time_seconds, cpu_usage, color=color, marker='o', label='CPU %')
ax1.tick_params(axis='y', labelcolor=color)
ax1.set_ylim(0, 100)

# RAM Line (Right Axis)
ax2 = ax1.twinx() 
color = 'tab:red'
ax2.set_ylabel('RAM Usage (MB)', color=color)
ax2.plot(time_seconds, ram_usage, color=color, marker='s', label='RAM (MB)')
ax2.tick_params(axis='y', labelcolor=color)
ax2.set_ylim(0, 200)

plt.title('System Resource Impact During Active Packet Sniffing')
fig.tight_layout()
plt.grid(alpha=0.3)
plt.show()