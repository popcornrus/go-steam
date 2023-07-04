package steam

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"strconv"
)

const (
	InventoryEndpoint = "https://steamcommunity.com/profiles/%d/inventory/json/%d/%d?"
)

type ItemTag struct {
	Category              string `json:"category"`
	InternalName          string `json:"internal_name"`
	LocalizedCategoryName string `json:"localized_category_name"`
	LocalizedTagName      string `json:"localized_tag_name"`
}

// Due to the JSON being string, etc... we cannot re-use EconItem
// Also, "assetid" is included as "id" not as assetid.
type InventoryItem struct {
	AppID      uint32        `json:"appid"`
	ContextID  uint64        `json:"contextid"`
	AssetID    uint64        `json:"id,string,omitempty"`
	ClassID    uint64        `json:"classid,string,omitempty"`
	InstanceID uint64        `json:"instanceid,string,omitempty"`
	Amount     uint64        `json:"amount,string"`
	Desc       *EconItemDesc `json:"-"` /* May be nil  */
}

type InventoryContext struct {
	ID         uint64 `json:"id,string"` /* Apparently context id needs at least 64 bits...  */
	AssetCount uint32 `json:"asset_count"`
	Name       string `json:"name"`
}

type InventoryAppStats struct {
	AppID            uint64                       `json:"appid"`
	Name             string                       `json:"name"`
	AssetCount       uint32                       `json:"asset_count"`
	Icon             string                       `json:"icon"`
	Link             string                       `json:"link"`
	InventoryLogo    string                       `json:"inventory_logo"`
	TradePermissions string                       `json:"trade_permissions"`
	Contexts         map[string]*InventoryContext `json:"rgContexts"`
}

var inventoryContextRegexp = regexp.MustCompile("var g_rgAppContextData = (.*?);")

func (session *Session) fetchInventory(
	sid SteamID,
	appID, contextID, startAssetID uint64,
	filters []Filter,
	items *[]InventoryItem,
) (hasMore bool, lastAssetID uint64, err error) {
	params := url.Values{
		"l": {session.language},
	}

	if startAssetID != 0 {
		params.Set("start_assetid", strconv.FormatUint(startAssetID, 10))
		params.Set("count", "75")
	} else {
		params.Set("count", "250")
	}

	resp, err := session.client.Get(fmt.Sprintf(InventoryEndpoint, sid, appID, contextID) + params.Encode())
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return false, 0, err
	}

	type Asset struct {
		Name       string `json:"name"`
		AppId      string `json:"appid,string"`
		AssetID    uint64 `json:"id,string"`
		ClassID    uint64 `json:"classid,string"`
		InstanceID uint64 `json:"instanceid,string"`
		Amount     uint64 `json:"amount,string"`
	}

	type Response struct {
		Success        bool                     `json:"success"`
		RGInventory    map[string]Asset         `json:"rgInventory"`
		RGDescriptions map[string]*EconItemDesc `json:"rgDescriptions"`
		More           bool                     `json:"more"`
		MoreStart      bool                     `json:"more_start"`
	}

	/*type Response struct {
		Assets              []Asset         `json:"assets"`
		Descriptions        []*EconItemDesc `json:"descriptions"`
		Success             int             `json:"success"`
		HasMore             int             `json:"more_items"`
		LastAssetID         string          `json:"last_assetid"`
		TotalInventoryCount int             `json:"total_inventory_count"`
		ErrorMsg            string          `json:"error"`
	}*/

	var response Response
	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false, 0, err
	}

	if response.Success == false {
		return false, 0, nil // empty inventory
	}

	// Fill in descriptions map, where key
	// is "<CLASS_ID>_<INSTANCE_ID>" pattern, and
	// value is position on asset description in
	// response.Descriptions array
	//
	// We need it for fast asset's description
	// searching in future
	descriptions := make(map[string]Asset)
	for _, desc := range response.RGInventory {
		key := fmt.Sprintf("%d_%d", desc.ClassID, desc.InstanceID)
		descriptions[key] = desc
	}

	for _, asset := range response.RGDescriptions {
		var (
			desc      *EconItemDesc
			assetItem Asset
		)

		key := fmt.Sprintf("%d_%d", asset.ClassID, asset.InstanceID)
		desc = response.RGDescriptions[key]
		assetItem = descriptions[key]

		item := InventoryItem{
			AppID:      uint32(appID),
			ContextID:  contextID,
			AssetID:    assetItem.AssetID,
			ClassID:    asset.ClassID,
			InstanceID: asset.InstanceID,
			Amount:     assetItem.Amount,
			Desc:       desc,
		}

		lastAssetID = assetItem.AssetID

		add := true
		for _, filter := range filters {
			add = filter(&item)
			if !add {
				break
			}
		}

		if add {
			*items = append(*items, item)
		}
	}

	hasMore = response.More != false
	if !hasMore {
		return hasMore, 0, nil
	}

	return hasMore, lastAssetID, nil
}

func (session *Session) GetInventory(sid SteamID, appID, contextID uint64, tradableOnly bool) ([]InventoryItem, error) {
	filters := []Filter{}

	if tradableOnly {
		filters = append(filters, IsTradable(tradableOnly))
	}

	return session.GetFilterableInventory(sid, appID, contextID, filters)
}

func (session *Session) GetFilterableInventory(sid SteamID, appID, contextID uint64, filters []Filter) ([]InventoryItem, error) {
	items := []InventoryItem{}
	startAssetID := uint64(0)

	for {
		hasMore, lastAssetID, err := session.fetchInventory(sid, appID, contextID, startAssetID, filters, &items)
		if err != nil {
			return nil, err
		}

		if !hasMore {
			break
		}

		startAssetID = lastAssetID
	}

	return items, nil
}

func (session *Session) GetInventoryAppStats(sid SteamID) (map[string]InventoryAppStats, error) {
	resp, err := session.client.Get("https://steamcommunity.com/profiles/" + sid.ToString() + "/inventory")
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	m := inventoryContextRegexp.FindSubmatch(body)
	if m == nil || len(m) != 2 {
		return nil, err
	}

	inven := map[string]InventoryAppStats{}
	if err = json.Unmarshal(m[1], &inven); err != nil {
		return nil, err
	}

	return inven, nil
}
