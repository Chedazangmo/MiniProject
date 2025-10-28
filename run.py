from __init__ import create_app

app = create_app()

# ADD THESE LINES FOR DEBUGGING
print("=== FLASK APP DEBUG INFO ===")
print(f"App name: {app.name}")
print(f"App instance path: {app.instance_path}")
print("Registered routes:")
for rule in app.url_map.iter_rules():
    print(f"  {rule.endpoint}: {rule.rule} -> {list(rule.methods)}")
print("=== DEBUG INFO END ===")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)