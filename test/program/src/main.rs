use std::thread;
use std::time::*;



fn main() {
	let step = 500;
	let max = 60000;
	
	println!("Starting with step size: {}s, and duration: {}s", step as f32 / 1000.0, max as f32 / 1000.0);
	
	
	let count_max = max / step;
	let timer = Instant::now();
	println!("{:12}s (0/{}) : Haven't crashed yet PagMan", 0.0, count_max);
	for count in 0..count_max {
		thread::sleep(Duration::from_millis(step));

		let elapsed = timer.elapsed().as_millis();
		println!("{:12}s ({}/{}) : Haven't crashed yet PagMan", elapsed as f64 / 1000.0, count + 1, count_max);
	}
	
	println!(":)");
	thread::sleep(Duration::from_millis(1000));
}
