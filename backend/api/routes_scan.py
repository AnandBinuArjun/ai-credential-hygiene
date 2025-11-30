def register_scan_routes(app, service):
    @app.post("/scan/start")
    def start_scan():
        # In a real app, run in background task
        return service.run_full_scan()

    @app.get("/scan/latest")
    def get_latest_scan():
        # TODO: Implement getting latest scan from DB
        return {"status": "unknown"}
