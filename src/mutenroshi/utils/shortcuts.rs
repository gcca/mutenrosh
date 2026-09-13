use std::collections::HashMap;

use mustache2::{
    Data,
    render::{RenderManager, SourceCache, provider::StaticProvider},
};

pub fn render(template: &'static str, context: Data) -> String {
    let cache = SourceCache::default();
    let provider = StaticProvider(HashMap::from([("template", template)]));
    let mut renderer = RenderManager::new(provider, &cache);
    renderer
        .render("template", context)
        .unwrap_or_else(|_| panic!("failed to render template"))
}

pub fn renders(template: &'static str) -> String {
    let cache = SourceCache::default();
    let provider = StaticProvider(HashMap::from([("template", template)]));
    let mut renderer = RenderManager::new(provider, &cache);
    renderer
        .render("template", Data::Null)
        .unwrap_or_else(|_| panic!("failed to render template"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_preserves_a_static_template() {
        assert_eq!(renders("static template"), "static template");
    }

    #[test]
    fn render_interpolates_caller_supplied_context() {
        let html = render(
            "Hello, {{name}}!",
            Data::map_from([("name".into(), Data::from("mutenroshi"))]),
        );
        assert_eq!(html, "Hello, mutenroshi!");
    }
}
