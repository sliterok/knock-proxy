import esbuild from 'esbuild';

esbuild.build({
	entryPoints: ["src/index.ts", 'src/adapter.js'],
	outdir: "dist",
	bundle: true,
	platform: "node",
	format: "esm",
	packages: "external",
});
