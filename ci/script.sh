# This script takes care of testing your crate

set -ex

# This is the "test phase", tweak it as you see fit
main() {
    cross build --target $TARGET $FEATURES
    cross build --target $TARGET $FEATURES --release

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET $FEATURES
    cross test --target $TARGET $FEATURES --release
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
