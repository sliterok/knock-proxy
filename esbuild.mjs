import esbuild from 'esbuild';

esbuild.build({
	entryPoints: ["src/index.ts"],
	outdir: "dist",
	bundle: true,
	platform: "node",
	format: "esm",
	packages: "external",
});
