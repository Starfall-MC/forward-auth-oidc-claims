tryit:
	RUST_LOG=debug cargo run -- -i ./secrets/client-id -s ./secrets/client-secret -u https://auth.starfallmc.space/realms/master --url http://127.0.0.1:8080 -k ./secrets/cookie-key -g