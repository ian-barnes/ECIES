# build.sh

# Rebuild static presentation

reveal-md slides.md --static docs/ --assets-dir assets
mkdir -p docs/assets
cp slides.css docs/assets/
