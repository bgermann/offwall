# This script takes care of testing your crate

set -ex

# This is the "test phase", tweak it as you see fit
main() {
    cross build --target $TARGET --all-features
    cross build --target $TARGET --all-features --release

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET --all-features
    cross test --target $TARGET --all-features --release
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
