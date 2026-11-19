gh auth login                                   # skip if already logged in
gh auth refresh -s read:packages,read:org
gh auth status                                  # confirm read:packages is listed

# trivy-cli-quicktasks
Cli commands and shell scripts for vulnerability scanning for Docker images in registries

```ORG= <xyz>   # the real org name, not the placeholder

gh api --paginate "/orgs/$ORG/packages?package_type=container" --jq '.[].name' |
while read -r PKG; do
  ENC=$(printf %s "$PKG" | sed 's|/|%2F|g')
  TAG=$(gh api "/orgs/$ORG/packages/container/$ENC/versions?per_page=100" \
    --jq '[.[] | select(.metadata.container.tags | length > 0)]
          | sort_by(.created_at) | last
          | .metadata.container.tags | map(select(. != "latest"))[0] // "latest"')
  echo "ghcr.io/$ORG/$PKG:$TAG"
done | tee images.txt```


run the script to find dependencies of images in ghcr

#!/usr/bin/env bash
**# scan-one-row.sh: run from the folder containing images.txt**
```export TRIVY_USERNAME=<xyz>
export TRIVY_PASSWORD=$(gh auth token)

OUT=images-summary.csv
echo "image,os,package_count,nginx_found,nginx_packages,all_packages" > "$OUT"

while read -r IMG; do
  [ -z "$IMG" ] && continue
  echo "Scanning $IMG ..." >&2

  trivy image --quiet --scanners vuln --list-all-pkgs --format json "$IMG" 2>/dev/null |
  jq -r --arg img "$IMG" '
    ([.Results[]?.Packages[]? | "\(.Name)@\(.Version)"] | unique) as $pkgs
    | [ $img,
        ((.Metadata.OS.Family // "unknown") + " " + (.Metadata.OS.Name // "")),
        ($pkgs | length),
        (if ($pkgs | map(select(test("nginx"; "i"))) | length) > 0 then "yes" else "no" end),
        ($pkgs | map(select(test("nginx"; "i"))) | join("; ")),
        ($pkgs | join("; ")) ]
    | @csv' >> "$OUT" \
  || echo "FAILED: $IMG" >> scan-errors.txt
done < images.txt

echo "Done -> $OUT" >&2```
