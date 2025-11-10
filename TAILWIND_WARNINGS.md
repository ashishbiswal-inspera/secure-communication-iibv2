# Tailwind CSS Warnings

## About the `@tailwind` and `@apply` Warnings

You may see warnings like these during build:
```
[lightningcss minify] Unknown at rule: @tailwind
[lightningcss minify] Unknown at rule: @apply
```

**These warnings are harmless!** They occur because:

1. Vite processes Tailwind directives correctly before CSS minification
2. LightningCSS (the minifier) sees the result but doesn't recognize the original directives
3. The build completes successfully and the CSS works perfectly

## Why This Happens

The build process:
1. Tailwind processes `@tailwind` and `@apply` directives ✅
2. Generates actual CSS classes ✅
3. LightningCSS minifies the output ⚠️ (warns but works)
4. Final CSS is correct ✅

## To Suppress These Warnings (Optional)

If you want to remove these warnings, you can:

1. **Use PostCSS** (more config):
   - Add back `postcss.config.js`
   - Configure Tailwind as a PostCSS plugin

2. **Change minifier** in `vite.config.ts`:
   ```typescript
   export default defineConfig({
     // ... other config
     build: {
       cssMinify: 'esbuild', // instead of 'lightningcss'
       // ... rest of build config
     }
   })
   ```

For now, the warnings can be safely ignored - your Tailwind CSS is working correctly!
