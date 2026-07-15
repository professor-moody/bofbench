let bofbenchMermaidSequence = 0;

document$.subscribe(async () => {
  mermaid.initialize({
    startOnLoad: false,
    securityLevel: "strict",
    theme: "dark",
    fontFamily: "var(--md-text-font-family)",
  });
  for (const block of document.querySelectorAll("pre.bb-diagram")) {
    const source = block.textContent;
    const id = `bofbench-mermaid-${bofbenchMermaidSequence++}`;
    const { svg } = await mermaid.render(id, source);
    const rendered = document.createElement("div");
    rendered.className = "bb-mermaid";
    rendered.innerHTML = svg;
    block.replaceWith(rendered);
  }
});
