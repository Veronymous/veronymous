use tonic_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("./proto/router_agent.proto")?;
    tonic_build::compile_protos("./proto/veronymous_token_info_service.proto")?;

    Ok(())
}
