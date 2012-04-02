#! /bin/sh
git archive --format tar --prefix libumberlog/ master | tar xf -

pandoc -t html5 libumberlog/README.rst >README.html
pandoc -t html5 libumberlog/lib/umberlog.rst >umberlog.3.html
sed '/@README@/r README.html' src/index.html.in | sed -e 's/<!-- @home@ -->/class="active"/' -e 's/<!-- @api@ -->//' >index.html
sed '/@README@/r umberlog.3.html' src/index.html.in | sed -e 's/<!-- @api@ -->/class="active"/' -e 's/<!-- @home@ -->//' >umberlog.html
cp libumberlog/data/umberlog-logo-full.png umberlog-logo.png
rm -rf libumberlog README.html umberlog.3.html
