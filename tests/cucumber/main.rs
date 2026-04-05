mod steps;
mod world;

use cucumber::World as _;
use world::E2eWorld;

#[tokio::main]
async fn main() {
    E2eWorld::cucumber()
        .max_concurrent_scenarios(1)
        .after(|_feature, _rule, _scenario, _ev, world| {
            Box::pin(async move {
                if let Some(world) = world {
                    steps::toxiproxy::cleanup_proxies(world).await;
                    // Clean up wizard temp directory
                    if !world.wizard_home.is_empty() {
                        let _ = std::fs::remove_dir_all(&world.wizard_home);
                    }
                }
            })
        })
        .run("tests/cucumber/features")
        .await;
}
