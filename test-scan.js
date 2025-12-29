// Test file for Impact Scan GitHub App
function testFunction() {
    // Intentional issues for Impact Scan to detect
    var x = eval("2 + 2"); // Security issue: eval usage
    console.log(x);

    // TODO: Fix this later
    // FIXME: This is broken

    if (x = 5) { // Bug: assignment instead of comparison
        console.log("This is wrong");
    }

    return null; // Potential null return
}

testFunction();
