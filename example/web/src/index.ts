const handleInputChange = (event: Event) => {
  const fReader = new FileReader();
  fReader.onload = (event) => {
    const buf = event.target?.result;
    import("office-crypto-wasm")
      .then((w) => w.decrypt(buf, "test"))
      .then(console.log);
  };
  const target = event.target as HTMLInputElement;
  if (target.files && target.files.length > 0) {
    fReader.readAsArrayBuffer(target.files[0]);
  }
};

function input() {
  const inputElement = document.createElement("input");
  inputElement.name = "myfile";
  inputElement.type = "file";
  inputElement.addEventListener("change", handleInputChange);
  return inputElement;
}

document.body.appendChild(input());
