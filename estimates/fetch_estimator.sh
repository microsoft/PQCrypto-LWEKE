
# lattice estimator
rm -rf lattice_estimator || true
git clone https://github.com/malb/lattice-estimator lattice_estimator
(
    cd lattice_estimator;
    git checkout 5ba00f56dd1086c3a42b98fc596c64907adb96ff;
    touch __init__.py
)
