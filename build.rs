fn main() {
    let input = "OutputDebugStringA";
    let bytes= input.as_bytes().to_owned();
    let mut bytes: Vec<String> = bytes.into_iter().map(|a:u8| format!("{}", a)).collect();
    bytes.push("0".to_owned());
    let bb = bytes.join(", ");
    dbg!(&bb);
    let input_up = input.to_uppercase();
    let res = format!("const {} :&[u16] = [{}];", input_up, &bb);
    dbg!(res);
}