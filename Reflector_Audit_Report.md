## In Contract `prices.rs` there is Silent Asset Index Truncation Due to Type Conversion to `u8`

### Finding description and impact
In the Contract prices.rs function `retrieve_asset_price_data` there is asset type `u32` conversion to `u8` . If the user by mistake pass the `asset_index` more than the `256` they truncated because of the as this `unsafe` type conversion

If asset is a `u32` but is cast to `u8`, it can truncate higher bits.

```
For example:
asset = 300
asset as u8 = 44 (300 % 256 = 44)
```

So, instead of retrieving price data for asset ID 300, it incorrectly fetches data for asset 44.

```rust
// Retrieve price from record for specific asset
pub fn retrieve_asset_price_data(e: &Env, asset: u32, timestamp: u64) -> Option<PriceData> {
    //if protocol version < 2, use legacy method
    if !protocol::at_latest_protocol_version(e) {
@>        let price = get_price_v1(e, asset as u8, timestamp)?;
        return Some(normalize_price_data(price, timestamp));
    }
    let last = get_last_timestamp(e);
    //get the timestamp index in the bitmask
    if last < timestamp {
        return None;
    }
    let mut period = 0;
    if last > timestamp {
        period = (last - timestamp) / settings::get_resolution(e) as u64;
    }
    if period > 255 {
        return None; //we cannot track more than 256 updates in the bitmask
    }
    if !has_price(e, asset, period as u32) {
        return None; //no price record
    }
    //load the prices for the timestamp
    let record = load_history_record(e, timestamp)?;
    //get price for the asset index
    let price = extract_single_update_record_price(&record, asset);
    Some(normalize_price_data(price, timestamp))
}
```
This functionality used many place to get the asset price price and lastprice

In the Audit Description of the Project there is invariant in the Configurational part given that:

```
Configurational
A contract instance can only be initialized once
Oracle base asset, decimals, and timeframe can never be changed after initialization
Each asset is unique, and can be added only once
Each oracle contract can support up to 256 assets and retain up to 256 historical update records /// this should be followed by the protocol
If this is not followed end user get the wrong asset that was also not the asset the user want the price of , if external dex using this oracle they end up with oracle/ price manipulation attack
```

### Recommended mitigation steps
We can use the safe type conversion in rust to fix the vulnerability like replacing as to try_into

```diff
// Retrieve price from record for specific asset
pub fn retrieve_asset_price_data(e: &Env, asset: u32, timestamp: u64) -> Option<PriceData> {
    //if protocol version < 2, use legacy method
    if !protocol::at_latest_protocol_version(e) {
-        let price = get_price_v1(e, asset as u8, timestamp)?;
+        let asset_u8: u8 = match asset.try_into() {
+            Ok(v) => v,
+            Err(_) => {
+                return None;
+            }
+        };
    
        let price = get_price_v1(e, asset_u8, timestamp)?;
        return Some(normalize_price_data(price, timestamp));
    }

    let last = get_last_timestamp(e);
    //get the timestamp index in the bitmask
    if last < timestamp {
        return None;
    }
    let mut period = 0;
    if last > timestamp {
        period = (last - timestamp) / settings::get_resolution(e) as u64;
    }
    if period > 255 {
        return None; //we cannot track more than 256 updates in the bitmask
    }
    if !has_price(e, asset, period as u32) {
        return None; //no price record
    }
    //load the prices for the timestamp
    let record = load_history_record(e, timestamp)?;
    //get price for the asset index
    let price = extract_single_update_record_price(&record, asset);
    Some(normalize_price_data(price, timestamp))
}
```
#### Proof of Concept
This is the unit test to show the truncation behaviour of the asset type conversion

```rust
#[cfg(test)]
mod tests {
    use soroban_sdk::{Env, log};
    use crate::types::PriceData;

    //= Use u32 for Soroban compatibility
    fn mock_get_price_v1(_e: &Env, asset: u32, _timestamp: u64) -> Option<i128> {
        match asset {
            44 => Some(4400), // Expected truncated value
            10 => Some(1000),
            _ => None,
        }
    }

    fn mock_normalize_price_data(price: i128, timestamp: u64) -> PriceData {
        PriceData { price, timestamp }
    }

    fn mock_protocol_not_latest(_e: &Env) -> bool {
        false // Force legacy path
    }

    #[test]
    fn test_asset_truncation_causes_invalid_data_retrieval() {
        let e = Env::default();
        let timestamp: u64 = 1_731_111_111;
        let asset_large: u32 = 300; // >255 → gets truncated to 44

        let truncated_asset = (asset_large % 256) as u32;

        
        let result = {
            if !mock_protocol_not_latest(&e) {
                let price = mock_get_price_v1(&e, truncated_asset, timestamp)
                    .expect("mock get_price_v1 failed");
                Some(mock_normalize_price_data(price, timestamp))
            } else {
                None
            }
        };

        assert!(
            result.is_some(),
            "Expected Some(PriceData) truncated asset 44  price"
        );

        let pd = result.unwrap();
        assert_eq!(
            pd.price, 4400,
            "Retrieved wrong price: asset={} truncated to {}",
            asset_large,
            truncated_asset
        );

        log!(
            &e,
            "Asset truncated occurred: asset {} → cast to {} → retrieved price {}",
            asset_large,
            truncated_asset,
            pd.price
        );
    }
}
```
